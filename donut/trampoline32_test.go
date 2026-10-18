package donut

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func disassembleAll32(t *testing.T, buf []byte, base uint64) []x86asm.Inst {
	t.Helper()
	var out []x86asm.Inst
	for off := 0; off < len(buf); {
		inst, err := x86asm.Decode(buf[off:], 32)
		if err != nil || inst.Len == 0 {
			t.Fatalf("x86 decode failure at offset %d (0x%x): err=%v bytes=% x",
				off, off, err, buf[off:min(off+8, len(buf))])
		}
		_ = base
		out = append(out, inst)
		off += inst.Len
	}
	return out
}

func gnu32(in x86asm.Inst) string { return x86asm.GNUSyntax(in, 0, nil) }

func TestGenerateTrampoline32_Decodes(t *testing.T) {
	for i := 0; i < 25; i++ {
		cipher, key, scheme, err := EncryptCore(make([]byte, 1024))
		if err != nil {
			t.Fatal(err)
		}
		fam, _ := evadeRandInt(3)
		seed, _ := evadeRandUint32()
		if seed == 0 {
			seed = 1
		}
		stage, err := GenerateTrampoline32(len(cipher), key, scheme, evadeHashFamily(fam), seed)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		insns := disassembleAll32(t, stage[:len(stage)-16], 0x400000)
		if len(insns) < 40 {
			t.Fatalf("iteration %d: suspiciously short stream: %d instructions", i, len(insns))
		}
	}
}

func TestGenerateTrampoline32_Contract(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 16)
	stage, err := GenerateTrampoline32(512, key, schemeXOR, hashDJB, 0x9e3779b9)
	if err != nil {
		t.Fatal(err)
	}
	code := stage[:len(stage)-16]
	insns := disassembleAll32(t, code, 0x400000)

	if !bytes.Contains(code, []byte{0x64, 0xa1, 0x30, 0, 0, 0}) {
		t.Fatal("no fs:[0x30] PEB access")
	}
	// Runtime-correct native x86 PEB/LDR offsets.
	if !bytes.Contains(code, []byte{0x8b, 0x40, 0x0c, 0x8d, 0x50, 0x14, 0x8b, 0x02}) {
		t.Fatal("native x86 PEB.Ldr/InMemoryOrder offsets are absent")
	}
	if len(code) < 5 || !bytes.Equal(code[:5], []byte{0x55, 0x89, 0xe5, 0x9c, 0x60}) {
		t.Fatalf("unexpected save prologue: % x", code[:min(5, len(code))])
	}
	foundPopad, foundPopfd := false, false
	for _, in := range insns {
		op := strings.ToLower(in.Op.String())
		foundPopad = foundPopad || strings.HasPrefix(op, "popa")
		foundPopfd = foundPopfd || strings.HasPrefix(op, "popf")
	}
	if !foundPopad || !foundPopfd {
		t.Fatalf("full restore missing: popad=%v popfd=%v", foundPopad, foundPopfd)
	}
	if !bytes.Contains(code, []byte{0x6a, 0x04}) || !bytes.Contains(code, []byte{0x6a, 0x20}) {
		t.Fatal("RW allocation or RX protection constant absent")
	}
	if !bytes.Contains(code, []byte{0x6a, 0xff}) {
		t.Fatal("FlushInstructionCache current-process pseudo-handle absent")
	}
	if !bytes.Contains(code, []byte{0x50, 0xc3}) {
		t.Fatal("balanced push eax; ret transfer absent")
	}
	if code[len(code)-1] != 0xc3 {
		t.Fatalf("quiet failure path must end in ret, got %#x", code[len(code)-1])
	}
}

func TestGenerateTrampoline32_KeyCipherLayoutAndSchemes(t *testing.T) {
	cases := []struct {
		scheme coreScheme
		step   []byte
	}{
		{schemeXOR, []byte{0x30, 0xd8}},
		{schemeADD, []byte{0x00, 0xcb, 0x28, 0xd8}},
		{schemeMBA, []byte{0x88, 0xc4, 0xf6, 0xd0, 0x20, 0xd8, 0xf6, 0xd3, 0x20, 0xe3, 0x08, 0xd8}},
	}
	for _, tc := range cases {
		key := make([]byte, 16)
		for i := range key {
			key[i] = byte(0x51 + i*3)
		}
		stage, err := GenerateTrampoline32(300, key, tc.scheme, hashROL, 7)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(stage[len(stage)-16:], key) {
			t.Fatalf("scheme %d: key is not the final 16-byte stage block", tc.scheme)
		}
		if !bytes.Contains(stage[:len(stage)-16], tc.step) {
			t.Fatalf("scheme %d: pinned decoder bytes absent", tc.scheme)
		}
		disassembleAll32(t, stage[:len(stage)-16], 0x400000)
	}
}

func TestGenerateTrampoline32_RejectsInvalidInputs(t *testing.T) {
	if _, err := GenerateTrampoline32(0, make([]byte, 16), schemeXOR, hashDJB, 1); err == nil {
		t.Fatal("zero core length accepted")
	}
	if _, err := GenerateTrampoline32(1, make([]byte, 15), schemeXOR, hashDJB, 1); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := GenerateTrampoline32(1, make([]byte, 16), coreScheme(99), hashDJB, 1); err == nil {
		t.Fatal("unknown scheme accepted")
	}
}
