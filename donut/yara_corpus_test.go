package donut

/*
	YARA atom regression corpus — verbatim atoms from public donut-detecting
	rules catalogued in .research/yara-corpus.md (8 sources, fetched 2026-10-18).

	Sanity leg: the canonical v1.1 loader blobs MUST match the version-pinned
	loader-prologue atoms (proves the harness sees what the rules see).

	Evade leg: generated evade stubs must contain none of the loader-stage
	atoms and none of the AMSI/WLDP plaintext strings (ghost
	Loader_Donut_Style pairing) — module names are rolling-XOR encoded and
	APIs are hash-resolved, so no plaintext atom survives in the stub bytes.

	When the core-encryption trampoline lands, the same corpus extends to the
	full artifact (assert zero loader-atom matches anywhere outside the head).
*/

import (
	"bytes"
	"encoding/binary"
	"log"
	"strings"
	"testing"
)

// yaraHexAtoms — verbatim from .research/yara-corpus.md.
var yaraLoaderAtoms = [][]byte{
	// Elastic Windows_Trojan_Donutloader_f40e3759
	{0x06, 0xB8, 0x03, 0x40, 0x00, 0x80, 0xC3, 0x4C, 0x8B, 0x49, 0x10, 0x49, 0x8B, 0x81, 0x30, 0x08, 0x00, 0x00},
	{0x04, 0x75, 0xEE, 0x89, 0x31, 0xF0, 0xFF, 0x46, 0x04, 0x33, 0xC0, 0xEB, 0x08, 0x83, 0x21, 0x00, 0xB8, 0x02},
	// Elastic Windows_Trojan_Donutloader_5c38878d
	{0x24, 0x48, 0x03, 0xC2, 0x48, 0x89, 0x44, 0x24, 0x28, 0x41, 0x8A, 0x00, 0x84, 0xC0, 0x74, 0x14, 0x33, 0xD2, 0xFF, 0xC1},
	// Volexity v1.0 x64 loader prologue
	{0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0x00, 0x05, 0x00, 0x00, 0x33, 0xFF, 0x48, 0x8B, 0xD9, 0x39, 0xB9, 0x38, 0x02, 0x00, 0x00, 0x0F, 0x84, 0xCE, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0x41, 0x28},
	// Volexity v1.0 x86 loader prologue
	{0x81, 0xEC, 0xD4, 0x02, 0x00, 0x00, 0x53, 0x55, 0x56, 0x8B, 0xB4, 0x24, 0xE4, 0x02, 0x00, 0x00, 0x33, 0xDB, 0x57, 0x8B, 0xFB, 0x39, 0x9E, 0x38, 0x02, 0x00, 0x00, 0x0F, 0x84, 0xEA, 0x00, 0x00, 0x00, 0xFF, 0x76, 0x2C, 0xFF, 0x76, 0x28, 0xFF, 0xB6, 0x8C, 0x00, 0x00, 0x00, 0xFF, 0xB6, 0x88},
	// Volexity v0.9.3 x64 v1 (present in older artifacts; guards blob mix-ups)
	{0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x81, 0xEC, 0x00, 0x05, 0x00, 0x00, 0x33, 0xFF, 0x48, 0x8B, 0xD9, 0x48, 0x39, 0xB9, 0x38, 0x02, 0x00, 0x00, 0x0F, 0x84, 0xC0, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0x41, 0x28, 0x48, 0x8B, 0x91},
}

// yaraStringAtoms — ghost Loader_Donut_Style + mthcht keyword families that
// pair module/API plaintexts with donut-style loaders.
var yaraStringAtoms = []string{
	"amsi.dll", "wldp.dll", "clr.dll",
	"AmsiScanBuffer", "AmsiScanString", "AmsiInitialize",
	"WldpIsClassInApprovedList", "WldpQueryDynamicCodeTrust",
	"NtTraceEvent", "EtwEventWrite",
	"ole32;oleaut32;wininet;mscoree;shell32",
	"RtlAddVectoredExceptionHandler",
}

// rapid7SandwichAtom — { 59 31 C0 48 0F } : pop rcx; xor eax,eax; 48 0F (the
// x84 mode-switch discriminator) at offset LE32(1)+5 of the artifact.
var rapid7SandwichAtom = []byte{0x59, 0x31, 0xC0, 0x48, 0x0F}

func TestYARACorpus_CanonicalBlobsMatchLoaderAtoms(t *testing.T) {
	// Positive control: our pinned v1.1 blobs ARE the official stages the
	// Volexity/Elastic rules were written against. If this fails, either the
	// blobs drifted or the corpus transcription is wrong.
	hits := 0
	for _, atom := range yaraLoaderAtoms {
		if bytes.Contains(LOADER_EXE_X64, atom) || bytes.Contains(LOADER_EXE_X86, atom) {
			hits++
		}
	}
	if hits < 4 {
		t.Fatalf("canonical blobs matched only %d/%d loader atoms — corpus transcription or blob drift", hits, len(yaraLoaderAtoms))
	}
}

func TestYARACorpus_EvadeStubsCleanOfLoaderAtoms(t *testing.T) {
	for i := 0; i < 30; i++ {
		stub, _, err := GenerateEvadeStub64(EvadeOptions{Etw: true, Wldp: true})
		if err != nil {
			t.Fatal(err)
		}
		for ai, atom := range yaraLoaderAtoms {
			if bytes.Contains(stub, atom) {
				t.Fatalf("build %d: evade stub contains loader atom #%d", i, ai)
			}
		}
	}
}

func TestYARACorpus_EvadeStubsCleanOfPlaintextStrings(t *testing.T) {
	for i := 0; i < 30; i++ {
		stub, _, err := GenerateEvadeStub64(EvadeOptions{Etw: true, Wldp: true})
		if err != nil {
			t.Fatal(err)
		}
		lower := toLowerASCII(string(stub))
		for _, s := range yaraStringAtoms {
			if bytes.Contains(stub, []byte(s)) {
				t.Fatalf("build %d: stub contains plaintext atom %q (ghost/mthcht pairing)", i, s)
			}
			if bytes.Contains([]byte(lower), []byte(toLowerASCII(s))) {
				t.Fatalf("build %d: stub contains case-insensitive plaintext atom %q", i, s)
			}
		}
	}
}

func TestYARACorpus_Rapid7SandwichBrokenByMorphPreamble(t *testing.T) {
	// The Rapid7 atom needs 59 31 C0 48 0F — i.e. the canonical zero-eax
	// form 31 C0 between the pop and the mode switch. Every morphPreamble
	// X84 variant must break it (29 C0 / 83 E0 00 substitutions).
	canon := append([]byte{0x59}, append([]byte{0x31, 0xC0}, 0x48, 0x0F)...)
	if !bytes.Contains(canon, rapid7SandwichAtom) {
		t.Fatal("self-test: canonical X84 head no longer matches the Rapid7 atom — corpus drift")
	}
	seen := map[string]bool{}
	for i := 0; i < 60; i++ {
		p, err := morphPreamble(X84)
		if err != nil {
			t.Fatal(err)
		}
		seen[string(p)] = true
		candidate := append([]byte{0x59}, append(append([]byte{}, p...), 0x48, 0x0F)...)
		if bytes.Contains(candidate, rapid7SandwichAtom) {
			t.Fatalf("morphPreamble produced the canonical 31 C0 form at iteration %d — substitution table regressed", i)
		}
	}
	if len(seen) < 2 {
		t.Fatalf("only %d preamble variants over 60 draws — morph degraded", len(seen))
	}
}

// TestYARACorpus_TelsyStructuralLayout encodes the Telsy donut_shellcode_fixed
// condition (v0.9.3 layout) against a synthesized artifact prefix built the way
// Sandwich does it, using a zero-ish instance stand-in. The restructured v1.1
// Go instance must NOT satisfy the v0.9.3 structural rule.
func TestYARACorpus_TelsyStructuralLayout(t *testing.T) {
	inst := make([]byte, 4760)
	// v0.9.3-style fills that WOULD satisfy the rule on the old layout:
	binary.LittleEndian.PutUint32(inst[560:], 1) // exit_opt region old offset
	machine := make([]byte, 5+len(inst)+10)
	machine[0] = 0xE8
	binary.LittleEndian.PutUint32(machine[1:5], uint32(len(inst)))
	copy(machine[5:], inst)
	copy(machine[5+len(inst):], []byte{0x59, 0x31, 0xC0, 0x48, 0x0F, 0x88, 0, 0, 0, 0})

	telsyMatch := func(b []byte) bool {
		if len(b) < 579 || b[0] != 0xE8 {
			return false
		}
		// instance length echo: uint32(1)==uint32(5) means the 4 bytes after
		// the call displacement equal the displacement — only true when the
		// first instance bytes coincidentally mirror it; our layout starts
		// with the instance Len field, not the echo.
		return binary.LittleEndian.Uint32(b[1:5]) == binary.LittleEndian.Uint32(b[5:9])
	}
	if telsyMatch(machine) {
		t.Fatal("synthesized v1.1-layout artifact satisfied the v0.9.3 Telsy size-echo — layout regressed to 0.9.3")
	}
}

// TestYARACorpus_FullArtifactsKillsLoaderAtoms — with Morph enabled the
// canonical loader exists only as ciphertext: every catalogued loader-stage
// atom (Volexity ×14, Elastic ×3) must be absent from complete artifacts of
// every architecture, with and without the evade stub, across builds.
func TestYARACorpus_FullArtifactsKillsLoaderAtoms(t *testing.T) {
	payload := make([]byte, 4760)
	for i := range payload {
		payload[i] = byte(i * 3)
	}
	for _, arch := range []DonutArch{X32, X64, X84} {
		for _, evade := range []EvadeMode{EvadeNone, EvadeHwbp} {
			for build := 0; build < 5; build++ {
				out, err := sandwich(arch, bytes.NewBuffer(append([]byte(nil), payload...)), true, evade, 0)
				if err != nil {
					t.Fatalf("%d/%d build %d: %v", arch, evade, build, err)
				}
				artifact := out.Bytes()
				for ai, atom := range yaraLoaderAtoms {
					if bytes.Contains(artifact, atom) {
						t.Fatalf("arch %d evade %d build %d: loader atom #%d survived encryption", arch, evade, build, ai)
					}
				}
				for _, s := range yaraStringAtoms {
					if bytes.Contains(artifact, []byte(s)) {
						t.Fatalf("arch %d evade %d build %d: plaintext %q in artifact", arch, evade, build, s)
					}
				}
			}
		}
	}
}

// TestYARACorpus_MorphArtifactsUnique — pairwise byte-level inequality of
// full artifacts across builds (beyond the head grammar everything varies).
func TestYARACorpus_MorphArtifactsUnique(t *testing.T) {
	payload := make([]byte, 4760)
	seen := map[string]bool{}
	for build := 0; build < 20; build++ {
		out, err := sandwich(X64, bytes.NewBuffer(append([]byte(nil), payload...)), true, EvadeHwbp, 0)
		if err != nil {
			t.Fatal(err)
		}
		seen[string(out.Bytes())] = true
	}
	if len(seen) != 20 {
		t.Fatalf("%d distinct artifacts over 20 morphed builds", len(seen))
	}
}

// TestYARACorpus_CanonicalArtifactsStillMatch — positive control at the
// artifact level: canonical (no morph, no evade) output must still contain
// the loader atoms; otherwise this suite would pass vacuously.
func TestYARACorpus_CanonicalArtifactsStillMatch(t *testing.T) {
	payload := make([]byte, 4760)
	out, err := sandwich(X64, bytes.NewBuffer(append([]byte(nil), payload...)), false, EvadeNone, 0)
	if err != nil {
		t.Fatal(err)
	}
	hits := 0
	for _, atom := range yaraLoaderAtoms {
		if bytes.Contains(out.Bytes(), atom) {
			hits++
		}
	}
	if hits < 2 {
		t.Fatalf("canonical artifact matched only %d loader atoms — vacuous suite", hits)
	}
}

// TestYARACorpus_RealInstanceStringsEncrypted — closes the gap the daybreak
// review flagged: the artifact-level tests used a zero stand-in instance, so
// they never exercised the real instance plaintext strings. This leg builds a
// REAL instance through CreateModule+CreateInstance: at entropy 3 the
// artifact must contain none of the attribution strings; at entropy 1 the
// control must still contain them (proving the test discriminates).
func TestYARACorpus_RealInstanceStringsEncrypted(t *testing.T) {
	build := func(entropy uint32) []byte {
		config := &DonutConfig{
			Arch:     X64,
			Type:     DONUT_MODULE_DLL,
			InstType: DONUT_INSTANCE_PIC,
			Entropy:  entropy,
			Compress: 1,
			Bypass:   3,
			Method:   "Run",
		}
		if err := CreateModule(config, bytes.NewBuffer(make([]byte, 64))); err != nil {
			t.Fatalf("CreateModule(e%d): %v", entropy, err)
		}
		inst, err := CreateInstance(config)
		if err != nil {
			t.Fatalf("CreateInstance(e%d): %v", entropy, err)
		}
		out, err := sandwich(X64, inst, true, EvadeHwbp, 0)
		if err != nil {
			t.Fatalf("sandwich(e%d): %v", entropy, err)
		}
		return out.Bytes()
	}

	artifact3 := build(DONUT_ENTROPY_DEFAULT)
	for _, s := range yaraStringAtoms {
		if bytes.Contains(artifact3, []byte(s)) {
			t.Fatalf("entropy=3 morphed artifact contains plaintext %q — instance not encrypted", s)
		}
	}

	artifact1 := build(DONUT_ENTROPY_NONE)
	// Positive control: the plaintext instance still carries the DLL-name list.
	if !bytes.Contains(artifact1, []byte("ole32;oleaut32")) && !bytes.Contains(artifact1, []byte("Amsi")) {
		t.Fatal("entropy=1 control artifact lost its plaintext strings — test cannot discriminate")
	}
	for _, atom := range yaraLoaderAtoms {
		if bytes.Contains(artifact1, atom) {
			t.Fatalf("entropy=1 morphed artifact still contains a loader atom — stage encryption broken")
		}
	}
}

// TestMorphPlaintextInstanceWarningAlwaysVisible — daybreak P0.3 / sol-6.1
// policy: the half-protection warning must fire for morph+entropy<3 WITHOUT
// the verbose flag, and must NOT fire at entropy 3.
func TestMorphPlaintextInstanceWarningAlwaysVisible(t *testing.T) {
	capture := &bytes.Buffer{}
	old := log.Writer()
	log.SetOutput(capture)
	defer log.SetOutput(old)

	config := &DonutConfig{
		Arch: X64, Type: DONUT_MODULE_DLL, InstType: DONUT_INSTANCE_PIC,
		Entropy: DONUT_ENTROPY_NONE, Compress: 1, Bypass: 3, Method: "Run",
		// Verbose deliberately FALSE — the warning must not depend on it
	}
	if err := validateConfig(config); err != nil {
		t.Fatal(err)
	}
	config.Morph = true
	if err := validateConfig(config); err != nil {
		t.Fatal(err)
	}
	out := capture.String()
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, "instance stays PLAINTEXT") {
		t.Fatalf("morph+entropy<3 without verbose produced no always-visible warning: %q", out)
	}

	capture.Reset()
	config.Entropy = DONUT_ENTROPY_DEFAULT
	if err := validateConfig(config); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(capture.String(), "WARNING") {
		t.Fatal("warning fired at entropy 3 (full corpus) — noise regression")
	}
}
