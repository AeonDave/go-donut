package donut

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
)

// Frozen v1.1 wire ordinals. Never construct expected values from api_imports.
var sehWireImports = [...]API_IMPORT{
	{"kernel32.dll", "LoadLibraryA"}, {"kernel32.dll", "GetProcAddress"},
	{"kernel32.dll", "GetModuleHandleA"}, {"kernel32.dll", "VirtualAlloc"},
	{"kernel32.dll", "VirtualFree"}, {"kernel32.dll", "VirtualQuery"},
	{"kernel32.dll", "VirtualProtect"}, {"kernel32.dll", "Sleep"},
	{"kernel32.dll", "MultiByteToWideChar"}, {"kernel32.dll", "GetUserDefaultLCID"},
	{"kernel32.dll", "WaitForSingleObject"}, {"kernel32.dll", "CreateThread"},
	{"kernel32.dll", "CreateFileA"}, {"kernel32.dll", "GetFileSizeEx"},
	{"kernel32.dll", "GetThreadContext"}, {"kernel32.dll", "GetCurrentThread"},
	{"kernel32.dll", "GetCurrentProcess"}, {"kernel32.dll", "GetCommandLineA"},
	{"kernel32.dll", "GetCommandLineW"}, {"kernel32.dll", "HeapAlloc"},
	{"kernel32.dll", "HeapReAlloc"}, {"kernel32.dll", "GetProcessHeap"},
	{"kernel32.dll", "HeapFree"}, {"kernel32.dll", "GetLastError"},
	{"kernel32.dll", "CloseHandle"}, {"shell32.dll", "CommandLineToArgvW"},
	{"oleaut32.dll", "SafeArrayCreate"}, {"oleaut32.dll", "SafeArrayCreateVector"},
	{"oleaut32.dll", "SafeArrayPutElement"}, {"oleaut32.dll", "SafeArrayDestroy"},
	{"oleaut32.dll", "SafeArrayGetLBound"}, {"oleaut32.dll", "SafeArrayGetUBound"},
	{"oleaut32.dll", "SysAllocString"}, {"oleaut32.dll", "SysFreeString"},
	{"oleaut32.dll", "LoadTypeLib"}, {"wininet.dll", "InternetCrackUrlA"},
	{"wininet.dll", "InternetOpenA"}, {"wininet.dll", "InternetConnectA"},
	{"wininet.dll", "InternetSetOptionA"}, {"wininet.dll", "InternetReadFile"},
	{"wininet.dll", "InternetQueryDataAvailable"}, // ordinal 40
	{"wininet.dll", "InternetCloseHandle"},        // ordinal 41
	{"wininet.dll", "HttpOpenRequestA"}, {"wininet.dll", "HttpSendRequestA"},
	{"wininet.dll", "HttpQueryInfoA"}, {"mscoree.dll", "CorBindToRuntime"},
	{"mscoree.dll", "CLRCreateInstance"}, {"ole32.dll", "CoInitializeEx"},
	{"ole32.dll", "CoCreateInstance"}, {"ole32.dll", "CoUninitialize"},
	{"ntdll.dll", "RtlEqualUnicodeString"}, {"ntdll.dll", "RtlEqualString"},
	{"ntdll.dll", "RtlUnicodeStringToAnsiString"}, {"ntdll.dll", "RtlInitUnicodeString"},
	{"ntdll.dll", "RtlExitUserThread"}, {"ntdll.dll", "RtlExitUserProcess"},
	{"ntdll.dll", "RtlCreateUnicodeString"}, {"ntdll.dll", "RtlGetCompressionWorkSpaceSize"},
	{"ntdll.dll", "RtlDecompressBuffer"}, {"ntdll.dll", "NtContinue"},
	{"ntdll.dll", "NtCreateSection"}, {"ntdll.dll", "NtMapViewOfSection"},
	{"ntdll.dll", "NtUnmapViewOfSection"},
}

func TestSEHFixedWireGolden(t *testing.T) {
	const wireSize, hashOffset, countOffset = 3424, 48, 572
	const x86SHA = "c1c9951c0d2856f5f21971226f69f994aefffd24198f92520dc04816b3ac6e71"
	if got := fmt.Sprintf("%x", sha256.Sum256(LOADER_EXE_X86)); got != x86SHA {
		t.Fatalf("x86 loader changed: %s", got)
	}
	if len(sehWireImports) != 63 || len(api_imports) != 63 {
		t.Fatalf("wire/producer eager count = %d/%d, want 63/63", len(sehWireImports), len(api_imports))
	}
	if sehWireImports[40] != (API_IMPORT{"wininet.dll", "InternetQueryDataAvailable"}) ||
		sehWireImports[41] != (API_IMPORT{"wininet.dll", "InternetCloseHandle"}) {
		t.Fatal("fixed WinInet slot 40/41 contract changed")
	}
	for i, want := range sehWireImports {
		if got := api_imports[i]; got != want {
			t.Fatalf("producer ordinal %d = %+v, want %+v", i, got, want)
		}
	}
	// Baseline is built from literal offsets/bytes, not a cloned instance's WriteTo output.
	var baseline DonutInstance
	baseline.Iv = 0x0102030405060708
	baseline.Hash[40] = 0x1122334455667788
	baseline.Hash[41] = 0x8877665544332211
	baseline.Hash[63] = 0xaabbccddeeff0011
	baseline.ExitOpt = 2
	baseline.Entropy = 1
	baseline.OEP = 0x12345678
	baseline.ApiCount = 63
	copy(baseline.DllNames[:], "KERNEL32;WININET")
	baseline.Mod_len = 0x0102030405060708
	golden := make([]byte, wireSize)
	binary.LittleEndian.PutUint64(golden[40:], 0x0102030405060708)
	binary.LittleEndian.PutUint64(golden[hashOffset+40*8:], 0x1122334455667788)
	binary.LittleEndian.PutUint64(golden[hashOffset+41*8:], 0x8877665544332211)
	binary.LittleEndian.PutUint64(golden[hashOffset+63*8:], 0xaabbccddeeff0011)
	binary.LittleEndian.PutUint32(golden[560:], 2)
	binary.LittleEndian.PutUint32(golden[564:], 1)
	binary.LittleEndian.PutUint32(golden[568:], 0x12345678)
	binary.LittleEndian.PutUint32(golden[countOffset:], 63)
	copy(golden[576:], "KERNEL32;WININET")
	binary.LittleEndian.PutUint64(golden[wireSize-8:], 0x0102030405060708)
	var buf bytes.Buffer
	baseline.WriteTo(&buf)
	if !bytes.Equal(buf.Bytes(), golden) {
		for i := range golden {
			if i >= buf.Len() {
				t.Fatalf("independent trailing-layout golden: short output at %d (size %d)", i, buf.Len())
			}
			if buf.Bytes()[i] != golden[i] {
				t.Fatalf("independent trailing-layout golden: offset %d, actual size %d, got %02x want %02x", i, buf.Len(), buf.Bytes()[i], golden[i])
			}
		}
		t.Fatalf("instance size %d, want %d", buf.Len(), wireSize)
	}
	for _, arch := range []DonutArch{X32, X64, X84} {
		for _, entropy := range []uint32{DONUT_ENTROPY_NONE, DONUT_ENTROPY_DEFAULT} {
			t.Run(fmt.Sprintf("arch%d_entropy%d", arch, entropy), func(t *testing.T) {
				cfg := DefaultConfig()
				cfg.Arch, cfg.Entropy, cfg.Bypass = arch, entropy, 0
				cfg.ModuleData = bytes.NewBuffer([]byte("benign"))
				serialized, err := CreateInstance(cfg)
				if err != nil {
					t.Fatal(err)
				}
				raw := serialized.Bytes()
				if len(raw) < wireSize || cfg.inst.ApiCount != 63 {
					t.Fatalf("short instance or ApiCount != 63: len=%d count=%d", len(raw), cfg.inst.ApiCount)
				}
				if entropy == DONUT_ENTROPY_NONE && binary.LittleEndian.Uint32(raw[countOffset:]) != 63 {
					t.Fatal("serialized ApiCount changed")
				}
				for i, imp := range sehWireImports {
					want := Maru([]byte(imp.Name), cfg.inst.Iv) ^ Maru([]byte(imp.Module), cfg.inst.Iv)
					if got := binary.LittleEndian.Uint64(raw[hashOffset+i*8:]); got != want {
						t.Fatalf("slot %d %s!%s got %x want %x", i, imp.Module, imp.Name, got, want)
					}
				}
				want := Maru([]byte("RtlAddFunctionTable"), cfg.inst.Iv) ^ Maru([]byte("ntdll.dll"), cfg.inst.Iv)
				if want == 0 || binary.LittleEndian.Uint64(raw[hashOffset+63*8:]) != want {
					t.Fatal("optional slot 63 changed")
				}
			})
		}
	}
}
