package donut

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

/*
	Polymorphic Mutation Engine for Donut loader stubs.

	Morph is deliberately generation-time only. It emits a copy of the
	canonical loader preceded by Intel-defined NOP-equivalent instructions and
	may select a safe X84 preamble substitution. The generated stage is never
	encoded and contains no self-modifying decoder, so the handoff can remain RX.
*/

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

// insertJunk prepends 2–12 bytes of random NOP-equivalent instruction
// sequences before the supplied code. The returned slice starts with junk
// NOPs followed by the original code bytes (unmodified). Since the original
// code is never encoded or changed, this operation is safe for stages handed
// off as RX.
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
		junk = append(junk, candidates[nopIndex]...)
	}

	out := make([]byte, 0, len(junk)+len(code))
	out = append(out, junk...)
	out = append(out, code...)
	return out, nil
}

// morphLoader applies generation-time variation to a complete loader stage.
// It deliberately returns a copy prefixed with NOP-equivalent instructions;
// the emitted stage contains the original executable bytes and has no runtime
// decoder or self-modifying write path.
func morphLoader(loader []byte) ([]byte, error) {
	if len(loader) == 0 {
		return nil, fmt.Errorf("morph: empty loader")
	}
	return insertJunk(append([]byte(nil), loader...))
}

// ---------- Preamble substitution ----------

// morphPreamble returns a semantically equivalent preamble for the given
// architecture, randomly choosing among instruction variants.
//
// X32: pop edx; push ecx; push edx (3 bytes, no variants)
// X84: xor eax,eax replaced with sub eax,eax or and eax,0
func morphPreamble(arch DonutArch) ([]byte, error) {
	switch arch {
	case X32:
		// pop edx(0x5A); push ecx(0x51); push edx(0x52)
		// No semantic alternatives that are shorter, but we can insert
		// NOP junk around the fixed instructions.
		return []byte{0x5A, 0x51, 0x52}, nil

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
