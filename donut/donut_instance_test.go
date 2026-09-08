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

func TestX64LoaderMatchesOfficialV11FinalStage(t *testing.T) {
	const rawCoreLength = 13430
	const finalStageLength = 13478
	const officialRawCoreSHA256 = "da0ac2320629d45cd2669a4a21003ecde56bd11f73fa8bfb21abec3863407a1f"

	if len(LOADER_EXE_X64) != finalStageLength {
		t.Fatalf("x64 final stage length = %d, want %d", len(LOADER_EXE_X64), finalStageLength)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(LOADER_EXE_X64[22:22+rawCoreLength])); got != officialRawCoreSHA256 {
		t.Fatalf("x64 raw core SHA-256 = %s, want official v1.1 %s", got, officialRawCoreSHA256)
	}
	for i, b := range LOADER_EXE_X64[22+rawCoreLength:] {
		if b != 0 {
			t.Fatalf("x64 final-stage padding byte %d = %#x, want zero", i, b)
		}
	}
}

func TestX86LoaderMatchesOfficialV11Tag(t *testing.T) {
	const officialLength = 11647
	const officialSHA256 = "0c29cccff1b027d57c467564a333e9ade455144649909a4b797b09b43002ac71"

	if len(LOADER_EXE_X86) != officialLength {
		t.Fatalf("x86 loader length = %d, want official v1.1 tag %d", len(LOADER_EXE_X86), officialLength)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(LOADER_EXE_X86)); got != officialSHA256 {
		t.Fatalf("x86 loader SHA-256 = %s, want official v1.1 tag %s", got, officialSHA256)
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
