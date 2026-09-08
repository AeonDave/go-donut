package donut

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

const morphTestPayloadLen = 96

func morphTestPayload() *bytes.Buffer {
	return bytes.NewBuffer(bytes.Repeat([]byte{0xA5}, morphTestPayloadLen))
}

func morphTestStageOffset() int {
	// call rel32 + instance + pop ecx
	return 5 + morphTestPayloadLen + 1
}

func morphTestX64Loader() []byte {
	const x64WrapperLen = 22
	const x64StagePadding = 26
	coreLen := len(LOADER_EXE_X64) - x64WrapperLen - x64StagePadding
	return LOADER_EXE_X64[:x64WrapperLen+coreLen]
}

func TestMorphFalsePreservesCanonicalLayouts(t *testing.T) {
	for _, arch := range []DonutArch{X32, X64, X84} {
		t.Run(fmt.Sprintf("arch-%d", arch), func(t *testing.T) {
			public, err := Sandwich(arch, morphTestPayload())
			if err != nil {
				t.Fatalf("Sandwich(%d): %v", arch, err)
			}
			private, err := sandwich(arch, morphTestPayload(), false)
			if err != nil {
				t.Fatalf("sandwich(%d, false): %v", arch, err)
			}
			if !bytes.Equal(public.Bytes(), private.Bytes()) {
				t.Fatal("Sandwich and sandwich(false) produced different bytes")
			}
			assertCanonicalLayout(t, arch, public.Bytes())
		})
	}
}

func TestMorphStaticOutputLayoutHasNoRuntimeDecoder(t *testing.T) {
	for _, arch := range []DonutArch{X32, X64, X84} {
		t.Run(fmt.Sprintf("arch-%d", arch), func(t *testing.T) {
			out, err := sandwich(arch, morphTestPayload(), true)
			if err != nil {
				t.Fatalf("sandwich(%d, true): %v", arch, err)
			}
			assertStaticMorphLayout(t, arch, out.Bytes())
		})
	}
}

func assertCanonicalLayout(t *testing.T, arch DonutArch, code []byte) {
	t.Helper()
	stage := morphTestStageOffset()
	if len(code) < stage {
		t.Fatalf("output length %d is shorter than stage offset %d", len(code), stage)
	}

	switch arch {
	case X32:
		assertBytesAt(t, code, stage, []byte{0x5A, 0x51, 0x52}, "x32 preamble")
		assertBytesAt(t, code, stage+3, LOADER_EXE_X86, "x32 loader")
	case X64:
		assertBytesAt(t, code, stage, LOADER_EXE_X64, "x64 loader")
	case X84:
		assertX84Layout(t, code, stage, false)
	default:
		t.Fatalf("unsupported test architecture %d", arch)
	}
}

func assertStaticMorphLayout(t *testing.T, arch DonutArch, code []byte) {
	t.Helper()
	stage := morphTestStageOffset()
	if len(code) < stage {
		t.Fatalf("output length %d is shorter than stage offset %d", len(code), stage)
	}

	switch arch {
	case X32:
		assertBytesAt(t, code, stage, []byte{0x5A, 0x51, 0x52}, "x32 preamble")
		assertStaticMorphBlock(t, code[stage+3:], LOADER_EXE_X86, "x32 loader")
	case X64:
		assertStaticMorphBlock(t, code[stage:], LOADER_EXE_X64, "x64 loader")
	case X84:
		assertX84Layout(t, code, stage, true)
	default:
		t.Fatalf("unsupported test architecture %d", arch)
	}
}

func assertX84Layout(t *testing.T, code []byte, stage int, morphed bool) {
	t.Helper()
	branchStart := -1
	for _, candidate := range []int{stage + 2, stage + 3} {
		if candidate+7 <= len(code) && bytes.Equal(code[candidate:candidate+3], []byte{0x48, 0x0F, 0x88}) {
			branchStart = candidate
			break
		}
	}
	if branchStart < 0 {
		t.Fatalf("x84 dispatch branch is missing at the preamble boundary")
	}
	if !morphed {
		if branchStart != stage+2 {
			t.Fatalf("canonical x84 dispatch branch starts at %d, want %d", branchStart, stage+2)
		}
		assertBytesAt(t, code, stage, []byte{0x31, 0xC0}, "canonical x84 preamble")
	} else {
		preamble := code[stage:branchStart]
		valid := bytes.Equal(preamble, []byte{0x31, 0xC0}) ||
			bytes.Equal(preamble, []byte{0x29, 0xC0}) ||
			bytes.Equal(preamble, []byte{0x83, 0xE0, 0x00})
		if !valid {
			t.Fatalf("morphed x84 preamble = %x", preamble)
		}
	}

	blockLenOffset := branchStart + 3
	blockStart := branchStart + 7
	blockLen := int(binary.LittleEndian.Uint32(code[blockLenOffset:blockStart]))
	if blockLen <= 0 || blockStart+blockLen > len(code) {
		t.Fatalf("x84 x64 block length %d exceeds output at offset %d", blockLen, blockStart)
	}
	shimStart := blockStart + blockLen
	assertBytesAt(t, code, shimStart, []byte{0x5A, 0x51, 0x52}, "x84 x32 shim")

	displacement := int64(int32(binary.LittleEndian.Uint32(code[branchStart+3 : blockStart])))
	target := int64(branchStart+7) + displacement
	if target != int64(shimStart) {
		t.Fatalf("x84 branch target = %d, want x32 shim at %d", target, shimStart)
	}

	x64Loader := morphTestX64Loader()
	x86Start := shimStart + 3
	if morphed {
		assertStaticMorphBlock(t, code[blockStart:shimStart], x64Loader, "x84 x64 loader")
		assertStaticMorphBlock(t, code[x86Start:], LOADER_EXE_X86, "x84 x86 loader")
	} else {
		assertBytesAt(t, code, blockStart, x64Loader, "x84 x64 loader")
		assertBytesAt(t, code, x86Start, LOADER_EXE_X86, "x84 x86 loader")
	}
}

func assertStaticMorphBlock(t *testing.T, block, canonical []byte, name string) {
	t.Helper()
	if len(block) < len(canonical)+2 {
		t.Fatalf("%s has length %d, want at least %d", name, len(block), len(canonical)+2)
	}
	rest, junkLen := stripLeadingMorphNops(block)
	if junkLen < 2 {
		t.Fatalf("%s has no required NOP variation prefix", name)
	}
	if len(rest) < len(canonical) || !bytes.Equal(rest[:len(canonical)], canonical) {
		t.Fatalf("%s does not end in the canonical loader; suffix starts %x", name, rest[:minInt(len(rest), 12)])
	}
	// Output layouts may have zero alignment padding after the final loader.
	// Any non-zero bytes after junk + canonical indicate an unexpected second
	// code region (including the former decoder+encoded composition).
	for _, b := range rest[len(canonical):] {
		if b != 0 {
			t.Fatalf("%s contains non-padding bytes after canonical loader", name)
		}
	}
}

func stripLeadingMorphNops(code []byte) ([]byte, int) {
	consumed := 0
	for consumed < len(code) {
		best := 0
		for _, nop := range nopEquivalents {
			if len(nop) > best && consumed+len(nop) <= len(code) &&
				bytes.Equal(code[consumed:consumed+len(nop)], nop) {
				best = len(nop)
			}
		}
		if best == 0 {
			break
		}
		consumed += best
	}
	return code[consumed:], consumed
}

func assertBytesAt(t *testing.T, code []byte, offset int, want []byte, name string) {
	t.Helper()
	if offset < 0 || offset+len(want) > len(code) {
		t.Fatalf("%s range [%d:%d] exceeds output length %d", name, offset, offset+len(want), len(code))
	}
	if !bytes.Equal(code[offset:offset+len(want)], want) {
		t.Fatalf("%s mismatch at offset %d", name, offset)
	}
}

func TestMorphRandomnessIsDeterministicAndVariesByReader(t *testing.T) {
	canonical := append([]byte(nil), LOADER_EXE_X64...)
	previous := rand.Reader
	t.Cleanup(func() { rand.Reader = previous })

	outputs := make([][]byte, 2)
	for i, value := range []byte{0x08, 0xFF} {
		rand.Reader = repeatingRandomReader(value)
		first, err := morphLoader(canonical)
		if err != nil {
			t.Fatalf("morphLoader(%#x): %v", value, err)
		}
		rand.Reader = repeatingRandomReader(value)
		second, err := morphLoader(canonical)
		if err != nil {
			t.Fatalf("second morphLoader(%#x): %v", value, err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("reader %#x did not produce deterministic output", value)
		}
		assertStaticMorphBlock(t, first, canonical, fmt.Sprintf("reader %#x output", value))
		outputs[i] = first
	}
	if bytes.Equal(outputs[0], outputs[1]) {
		t.Fatal("controlled readers produced identical Morph output")
	}
}

func TestMorphPropagatesRandomReaderFailure(t *testing.T) {
	replaceRandomReader(t, randomSourceFailure{})
	for _, arch := range []DonutArch{X32, X64, X84} {
		_, err := sandwich(arch, morphTestPayload(), true)
		if !errors.Is(err, errRandomSourceFailure) {
			t.Fatalf("sandwich(%d, true) error = %v; want injected source error", arch, err)
		}
	}
}

func TestMorphInputValidationAndBoundedRandomRejection(t *testing.T) {
	if _, err := randIntn(0); err == nil {
		t.Fatal("randIntn(0) returned nil error")
	}

	if out, err := morphLoader(nil); err == nil || out != nil {
		t.Fatalf("morphLoader(nil) = %v, %v; want nil output and error", out, err)
	}

	if _, err := morphPreamble(DonutArch(99)); err == nil {
		t.Fatal("morphPreamble(invalid architecture) returned nil error")
	}

	replaceRandomReader(t, repeatingRandomReader(0x00))
	if _, err := randIntn(3); err == nil || !strings.Contains(err.Error(), "128") {
		t.Fatalf("randIntn(3) with a rejecting reader = %v; want bounded rejection error", err)
	}
}

func TestMorphGenerationIsConcurrentAndLeavesCanonicalLoadersUntouched(t *testing.T) {
	x86Before := append([]byte(nil), LOADER_EXE_X86...)
	x64Before := append([]byte(nil), LOADER_EXE_X64...)
	const workers = 24
	const iterations = 20
	var wg sync.WaitGroup
	errs := make(chan error, workers*iterations)
	for worker := 0; worker < workers; worker++ {
		arch := []DonutArch{X32, X64, X84}[worker%3]
		wg.Add(1)
		go func(arch DonutArch) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				out, err := sandwich(arch, morphTestPayload(), true)
				if err != nil {
					errs <- err
					return
				}
				if out == nil || out.Len() == 0 {
					errs <- fmt.Errorf("architecture %d returned empty output", arch)
					return
				}
			}
		}(arch)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if !bytes.Equal(LOADER_EXE_X86, x86Before) {
		t.Fatal("Morph generation modified the x86 loader global")
	}
	if !bytes.Equal(LOADER_EXE_X64, x64Before) {
		t.Fatal("Morph generation modified the x64 loader global")
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
