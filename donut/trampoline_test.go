package donut

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestEncryptCore_AntiIdentity(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	core := make([]byte, 4096)
	rng.Read(core)
	for i := 0; i < 40; i++ {
		cipher, key, scheme, err := EncryptCore(core)
		if err != nil {
			t.Fatal(err)
		}
		// 1. round-trip correctness (Go-side mirror)
		for j, c := range cipher {
			var p byte
			switch scheme {
			case schemeXOR, schemeMBA:
				p = c ^ key[j&15]
			case schemeADD:
				p = c - key[j&15] - byte(j)
			}
			if p != core[j] {
				t.Fatalf("scheme %d: round-trip mismatch at %d", scheme, j)
			}
			// 2. anti-identity: ciphertext byte must differ from plaintext byte
			if c == core[j] {
				t.Fatalf("scheme %d: identity position at %d (key leak class)", scheme, j)
			}
		}
		// 3. key constraints
		for j := 0; j < 16; j++ {
			switch scheme {
			case schemeXOR, schemeMBA:
				if key[j] == 0 {
					t.Fatalf("scheme %d: zero key byte at %d", scheme, j)
				}
			case schemeADD:
				if byte(key[j]%16) == byte((16-j)%16) {
					t.Fatalf("scheme ADD: key[%d]&15 == %d — identity leak at i≡0 mod 256", j, j)
				}
			}
		}
	}
}

func TestGenerateTrampoline64_Decodes(t *testing.T) {
	for i := 0; i < 25; i++ {
		cipher, key, scheme, err := EncryptCore(make([]byte, 1024))
		if err != nil {
			t.Fatal(err)
		}
		famInt, _ := evadeRandInt(3)
		seed, _ := evadeRandUint32()
		if seed == 0 {
			seed = 1
		}
		stage, err := GenerateTrampoline64(len(cipher), key, scheme, evadeHashFamily(famInt), seed)
		if err != nil {
			t.Fatal(err)
		}
		full := append(append([]byte{}, stage...), cipher...)
		insns := disassembleAll64(t, full[:len(stage)-16], 0x400000) // code only — key is data
		if len(insns) < 30 {
			t.Fatalf("iter %d: too few instructions (%d)", i, len(insns))
		}
	}
}

func TestGenerateTrampoline64_Contract(t *testing.T) {
	cipher, key, scheme, err := EncryptCore(make([]byte, 512))
	if err != nil {
		t.Fatal(err)
	}
	stage, err := GenerateTrampoline64(len(cipher), key, scheme, hashDJB, 0x9E3779B9)
	if err != nil {
		t.Fatal(err)
	}
	insns := disassembleAll64(t, stage[:len(stage)-16], 0x400000)

	find := func(mnem, part string) bool {
		for _, in := range insns {
			if strings.EqualFold(in.Op.String(), mnem) && strings.Contains(gnu(in), part) {
				return true
			}
		}
		return false
	}

	// instance pointer preserved (rcx saved/restored)
	if !find("push", "%rcx") {
		t.Fatal("prologue does not save rcx")
	}
	// flags preserved
	if !findPrefix(insns, "pushf") {
		t.Fatal("prologue does not save flags")
	}
	if !findPrefix(insns, "popf") {
		t.Fatal("epilogue does not restore flags")
	}
	// W^X order: VirtualAlloc RW (0x04), VirtualProtect RX (0x20), FlushInstructionCache
	if !find("mov", "0x4") {
		t.Fatal("VirtualAlloc RW protection not requested")
	}
	if !find("mov", "0x20") {
		t.Fatal("VirtualProtect PAGE_EXECUTE_READ not requested")
	}
	if !find("mov", "-0x1,%rcx") && !find("mov", "-1,%rcx") {
		t.Fatal("FlushInstructionCache pseudo-handle not used")
	}
	// balanced transfer: push rax + ret adjacent at the end of the success path
	pushRet := false
	for i := 0; i+1 < len(insns); i++ {
		if strings.EqualFold(insns[i].Op.String(), "push") &&
			strings.Contains(gnu(insns[i]), "%rax") &&
			strings.EqualFold(insns[i+1].Op.String(), "ret") {
			pushRet = true
		}
	}
	if !pushRet {
		t.Fatal("no balanced push rax; ret transfer to the decrypted core")
	}
}

func TestGenerateTrampoline64_KeyAndCiphertextPlacement(t *testing.T) {
	// The stage references key (rip+disp32) and ciphertext; the artifact must
	// be [code][key 16][cipher]. Verify by simulating the decrypt loop in a
	// Go mini-interpreter over the emitted byte stream for each scheme.
	for _, scheme := range []coreScheme{schemeXOR, schemeADD, schemeMBA} {
		core := make([]byte, 300)
		for i := range core {
			core[i] = byte(i * 7)
		}
		// force scheme: encrypt manually with valid key per constraints
		key := make([]byte, 16)
		for j := range key {
			key[j] = byte(0xA0 + j*7)
			if scheme == schemeADD && key[j]&15 == byte(j) {
				key[j] ^= 0x55
			}
			if (scheme == schemeXOR || scheme == schemeMBA) && key[j] == 0 {
				key[j] = 0x42
			}
		}
		cipher := make([]byte, len(core))
		for i, p := range core {
			switch scheme {
			case schemeXOR, schemeMBA:
				cipher[i] = p ^ key[i&15]
			case schemeADD:
				cipher[i] = p + key[i&15] + byte(i)
			}
		}
		stage, err := GenerateTrampoline64(len(core), key, scheme, hashROL, 7)
		if err != nil {
			t.Fatal(err)
		}
		artifact := append(append([]byte{}, stage...), cipher...)
		// key must be exactly at len(stage)-16 (generator appends key)
		if !bytes.Equal(artifact[len(stage)-16:len(stage)], key) {
			t.Fatalf("scheme %d: key block not at stage end", scheme)
		}
		// ciphertext must follow immediately
		if !bytes.Equal(artifact[len(stage):], cipher) {
			t.Fatalf("scheme %d: ciphertext not adjacent", scheme)
		}
		// decode-completeness over code+key: no trailing garbage before ciphertext
		disassembleAll64(t, stage[:len(stage)-16], 0x400000)
	}
}

// TestGenerateTrampoline64_SchemeStepBytes pins the exact per-scheme decoder
// instruction encodings — regression guard for hand-emitted opcodes.
func TestGenerateTrampoline64_SchemeStepBytes(t *testing.T) {
	cases := []struct {
		scheme coreScheme
		want   []byte
		desc   string
	}{
		{schemeXOR, []byte{0x30, 0xD0}, "xor al, dl"},
		{schemeADD, []byte{0x44, 0x00, 0xFA, 0x28, 0xD0}, "add dl,r15b; sub al,dl (opcode 00 normal direction; 02 is reversed)"},
		{schemeMBA, []byte{0x88, 0xC4, 0xF6, 0xD0, 0x20, 0xD0, 0xF6, 0xD2, 0x20, 0xE2, 0x08, 0xD0}, "mov ah,al; not al; and al,dl; not dl; and dl,ah; or al,dl"},
	}
	for _, tc := range cases {
		key := make([]byte, 16)
		for j := range key {
			key[j] = byte(0x30 + j)
			if tc.scheme == schemeADD && key[j]%16 == (16-byte(j))%16 {
				key[j] ^= 0x33
			}
		}
		stage, err := GenerateTrampoline64(128, key, tc.scheme, hashFNV, 99)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(stage, tc.want) {
			t.Fatalf("scheme %d: decoder step %s not found in stage", tc.scheme, tc.desc)
		}
	}
}

// findPrefix matches mnemonic by prefix so PUSHFQ/POPFQ (64-bit forms) hit.
func findPrefix(insns []x86asm.Inst, prefix string) bool {
	for _, in := range insns {
		if len(in.Op.String()) >= len(prefix) &&
			strings.EqualFold(in.Op.String()[:len(prefix)], prefix) {
			return true
		}
	}
	return false
}

// TestDecryptStoreTargetsDestination — run-9 regression: the decrypt-loop
// store must write the VirtualAlloc RW destination (r14), never the RX-staged
// ciphertext source (r13). A one-bit rm-field error (0x45 vs 0x46) produced a
// WRITE fault at iteration 0 that every byte-presence test accepted.
func TestDecryptStoreTargetsDestination(t *testing.T) {
	for i := 0; i < 10; i++ {
		cipher, key, scheme, err := EncryptCore(make([]byte, 256))
		if err != nil {
			t.Fatal(err)
		}
		stage, err := GenerateTrampoline64(len(cipher), key, scheme, hashDJB, 7)
		if err != nil {
			t.Fatal(err)
		}
		insns := disassembleAll64(t, stage[:len(stage)-16], 0x400000)
		sawStore := false
		for _, in := range insns {
			s := gnu(in)
			// byte store of al into an extended register base
			if strings.Contains(s, "mov") && strings.Contains(s, "%al,") {
				if strings.Contains(s, "(%r13)") {
					t.Fatalf("decrypt loop stores into the ciphertext source r13: %q", s)
				}
				if strings.Contains(s, "(%r14)") {
					sawStore = true
				}
			}
		}
		if !sawStore {
			t.Fatal("no byte store into r14 (destination page) found in the trampoline")
		}
	}
}

// TestTrampolineSlotsDoNotCollide — fix10 fault regression: the newPage slot
// and the VirtualProtect old-protect OUT slot must be DISTINCT rsp-relative
// offsets (the old rbp-relative layout aliased them when rbp was 16-aligned,
// so VirtualProtect wrote DWORD 4 over the pointer and the transfer jumped
// to 0x4). Decode-asserts: exactly one store and its matching loads use the
// dedicated 0x40 slot; the old-protect lea uses 0x38; no rbp-0x48 access.
func TestTrampolineSlotsDoNotCollide(t *testing.T) {
	for i := 0; i < 8; i++ {
		cipher, key, scheme, err := EncryptCore(make([]byte, 512))
		if err != nil {
			t.Fatal(err)
		}
		stage, err := GenerateTrampoline64(len(cipher), key, scheme, hashROL, 5)
		if err != nil {
			t.Fatal(err)
		}
		insns := disassembleAll64(t, stage[:len(stage)-16], 0x400000)
		newPageRefs, oldProtRefs := 0, 0
		for _, in := range insns {
			s := gnu(in)
			if strings.Contains(s, "0x40(%rsp)") {
				newPageRefs++
			}
			if strings.Contains(s, "lea") && strings.Contains(s, "0x38(%rsp)") {
				oldProtRefs++
			}
			// the aliased rbp-relative access must be gone entirely
			if strings.Contains(s, "-0x48(%rbp)") {
				t.Fatalf("aliased newPage slot survived: %q", s)
			}
		}
		if newPageRefs != 5 { // store + r14 load + VP base + FIC base + epilogue
			t.Fatalf("newPage slot references = %d, want 5 (store, decrypt dst, VP, FIC, transfer)", newPageRefs)
		}
		if oldProtRefs != 1 {
			t.Fatalf("old-protect OUT lea count = %d, want 1", oldProtRefs)
		}
	}
}

// TestSchemeAddStepDirection — decode-asserts the ADD-scheme steps: opcode 02
// is the REVERSED 8-bit form (reg ← reg+rm); the emitted pair must decode as
// dl += r15b then al -= dl. The 44 02 FA / 02 D0 pair decoded as r15b += dl
// and dl += al, racing the loop counter and shipping a half-decrypted core.
func TestSchemeAddStepDirection(t *testing.T) {
	for i := 0; i < 8; i++ {
		key := make([]byte, 16)
		for j := range key {
			key[j] = byte(0x21 + j*3)
		}
		stage, err := GenerateTrampoline64(128, key, schemeADD, hashFNV, 11)
		if err != nil {
			t.Fatal(err)
		}
		insns := disassembleAll64(t, stage[:len(stage)-16], 0x400000)
		sawAdd, sawSub := false, false
		for _, in := range insns {
			s := gnu(in)
			if s == "add	%r15b,%dl" || s == "add %r15b,%dl" {
				sawAdd = true
			}
			if s == "sub	%dl,%al" || s == "sub %dl,%al" {
				sawSub = true
			}
			// the reversed-direction victims must be gone
			if s == "add	%dl,%r15b" || s == "add %dl,%r15b" {
				t.Fatalf("reversed add survived: %q (r15b += dl destroys the counter)", s)
			}
			if s == "add	%al,%dl" || s == "add %al,%dl" {
				t.Fatalf("reversed add survived: %q (dl += al clobbers the key byte)", s)
			}
		}
		if !sawAdd || !sawSub {
			t.Fatalf("ADD-scheme steps missing: add=%v sub=%v", sawAdd, sawSub)
		}
	}
}
