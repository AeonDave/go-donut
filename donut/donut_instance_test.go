package donut

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestX64LoaderKeepsV11StackAlignmentPreamble(t *testing.T) {
	want := []byte{
		0x55,             // push rbp
		0x48, 0x89, 0xe5, // mov rbp, rsp
		0x48, 0x83, 0xe4, 0xf0, // and rsp, -16
		0x48, 0x83, 0xec, 0x20, // sub rsp, 32-byte shadow space
		0xe8, 0x05, 0x00, 0x00, 0x00, // call loader core
		0x48, 0x89, 0xec, // mov rsp, rbp
		0x5d, 0xc3, // pop rbp; ret
	}
	if !bytes.HasPrefix(LOADER_EXE_X64, want) {
		t.Fatalf("x64 loader lost the v1.1 stack-alignment preamble")
	}
}

func TestX64LoaderMatchesOfficialV11PatchedFinalStage(t *testing.T) {
	const rawCoreLength = 13430
	const finalStageLength = 13478
	const patchedRawCoreSHA256 = "d63fc4e0634e096ed4f655194d51cdabddbf1b6801431b25f2b0651201917d88"
	const relocationFixOffset = 22 + 0x227d

	if len(LOADER_EXE_X64) != finalStageLength {
		t.Fatalf("x64 final stage length = %d, want %d", len(LOADER_EXE_X64), finalStageLength)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(LOADER_EXE_X64[22:22+rawCoreLength])); got != patchedRawCoreSHA256 {
		t.Fatalf("x64 patched raw core SHA-256 = %s, want source-guided v1.1 patch %s", got, patchedRawCoreSHA256)
	}
	if got, want := LOADER_EXE_X64[relocationFixOffset:relocationFixOffset+4], []byte{0x90, 0x90, 0x90, 0x90}; !bytes.Equal(got, want) {
		t.Fatalf("x64 relocation fix at core raw offset 0x227d = % x, want NOPs", got)
	}
	for i, b := range LOADER_EXE_X64[22+rawCoreLength:] {
		if b != 0 {
			t.Fatalf("x64 final-stage padding byte %d = %#x, want zero", i, b)
		}
	}
}

func TestX86LoaderMatchesOfficialV11PatchedTag(t *testing.T) {
	const officialLength = 11647
	const patchedSHA256 = "c1c9951c0d2856f5f21971226f69f994aefffd24198f92520dc04816b3ac6e71"
	const relocationFixOffset = 0x1f4f

	if len(LOADER_EXE_X86) != officialLength {
		t.Fatalf("x86 patched loader length = %d, want official v1.1 core length %d", len(LOADER_EXE_X86), officialLength)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(LOADER_EXE_X86)); got != patchedSHA256 {
		t.Fatalf("x86 patched loader SHA-256 = %s, want source-guided v1.1 patch %s", got, patchedSHA256)
	}
	if got, want := LOADER_EXE_X86[relocationFixOffset:relocationFixOffset+3], []byte{0x90, 0x90, 0x90}; !bytes.Equal(got, want) {
		t.Fatalf("x86 relocation fix at raw offset 0x1f4f = % x, want NOPs", got)
	}
}

func TestV11ArchitectureValuesAndInstanceLayout(t *testing.T) {
	if X32 != 1 || X64 != 2 || X84 != 3 {
		t.Fatalf("architecture values = %d, %d, %d; want 1, 2, 3", X32, X64, X84)
	}

	config := DefaultConfig()
	config.Entropy = DONUT_ENTROPY_NONE
	config.ModuleData = bytes.NewBuffer(nil)
	serialized, err := CreateInstance(config)
	if err != nil {
		t.Fatalf("CreateInstance() error = %v", err)
	}
	if got := len(serialized.Bytes()); got != 4760 {
		t.Fatalf("serialized v1.1 instance length = %d, want 4760", got)
	}
}

func serializedInstanceForEntropy(t *testing.T, entropy uint32) []byte {
	t.Helper()

	config := DefaultConfig()
	config.Entropy = entropy
	config.ModuleData = bytes.NewBuffer([]byte("module-data"))

	serialized, err := CreateInstance(config)
	if err != nil {
		t.Fatalf("CreateInstance() error = %v", err)
	}

	return append([]byte(nil), serialized.Bytes()...)
}

func TestCreateInstanceWithoutEntropyIsDeterministic(t *testing.T) {
	first := serializedInstanceForEntropy(t, DONUT_ENTROPY_NONE)
	second := serializedInstanceForEntropy(t, DONUT_ENTROPY_NONE)

	if !bytes.Equal(first, second) {
		t.Fatal("CreateInstance() with Entropy=NONE produced different serialized instances")
	}
}

func TestCreateInstanceRejectsUnsupportedDefaultEntropy(t *testing.T) {
	config := DefaultConfig()
	config.Entropy = DONUT_ENTROPY_DEFAULT
	config.ModuleData = bytes.NewBuffer([]byte("module-data"))

	if _, err := CreateInstance(config); err == nil {
		t.Fatal("CreateInstance() with unsupported default entropy returned nil error")
	}
}

func TestPublicEntryPointsRejectNilInputs(t *testing.T) {
	if _, err := ShellcodeFromURL("http://127.0.0.1", nil); err == nil {
		t.Fatal("ShellcodeFromURL(nil config) error = nil")
	}
	if _, err := ShellcodeFromFile("missing.exe", nil); err == nil {
		t.Fatal("ShellcodeFromFile(nil config) error = nil")
	}
	if _, err := ShellcodeFromBytes(nil, DefaultConfig()); err == nil {
		t.Fatal("ShellcodeFromBytes(nil input) error = nil")
	}
	if err := CreateModule(nil, bytes.NewBuffer(nil)); err == nil {
		t.Fatal("CreateModule(nil config) error = nil")
	}
	if _, err := CreateInstance(DefaultConfig()); err == nil {
		t.Fatal("CreateInstance(nil module data) error = nil")
	}
	if _, err := Sandwich(0, bytes.NewBuffer(nil)); err == nil {
		t.Fatal("Sandwich(invalid architecture) error = nil")
	}
}

func TestCreateInstanceSerializesV11ThreadExitAPI(t *testing.T) {
	config := DefaultConfig()
	config.Entropy = DONUT_ENTROPY_NONE
	config.Thread = 1
	config.ModuleData = bytes.NewBuffer(nil)

	serialized, err := CreateInstance(config)
	if err != nil {
		t.Fatalf("CreateInstance() error = %v", err)
	}

	want := []byte("ExitProcess;exit;_exit;_cexit;_c_exit;quick_exit;_Exit;_o_exit")
	if !bytes.Contains(serialized.Bytes(), want) {
		t.Fatalf("serialized instance does not contain complete thread exit API list %q", want)
	}
}
