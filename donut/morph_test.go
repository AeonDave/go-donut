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
	"time"
)

func TestSandwichMorphSupportsAllArchitectures(t *testing.T) {
	payload := bytes.Repeat([]byte{0xA5}, 96)

	for _, arch := range []DonutArch{X32, X64, X84} {
		t.Run(fmt.Sprintf("arch-%d", arch), func(t *testing.T) {
			canonical, err := Sandwich(arch, bytes.NewBuffer(append([]byte(nil), payload...)))
			if err != nil {
				t.Fatalf("Sandwich(%d): %v", arch, err)
			}
			out, err := sandwich(arch, bytes.NewBuffer(append([]byte(nil), payload...)), true)
			if err != nil {
				t.Fatalf("sandwich(%d, morph=true): %v", arch, err)
			}
			if out == nil || out.Len() == 0 {
				t.Fatalf("sandwich(%d, morph=true) returned empty output", arch)
			}
			if !bytes.Contains(out.Bytes(), payload) {
				t.Fatalf("sandwich(%d, morph=true) lost the instance bytes", arch)
			}
			if bytes.Equal(out.Bytes(), canonical.Bytes()) {
				t.Fatalf("sandwich(%d, morph=true) is identical to canonical Sandwich output", arch)
			}
		})
	}
}

func TestMorphX84BranchTargetsX32Shim(t *testing.T) {
	const payloadLen = 96
	out, err := sandwich(X84, bytes.NewBuffer(bytes.Repeat([]byte{0}, payloadLen)), true)
	if err != nil {
		t.Fatalf("sandwich(X84, morph=true): %v", err)
	}
	code := out.Bytes()

	// call rel32 + instance + pop ecx precede the x84 dispatch sequence.
	branchStart := 5 + payloadLen + 1
	branchEnd := -1
	for i := branchStart; i+6 < len(code) && i < branchStart+8; i++ {
		if code[i] == 0x48 && code[i+1] == 0x0F && code[i+2] == 0x88 {
			branchStart = i
			branchEnd = i + 7
			break
		}
	}
	if branchEnd < 0 {
		t.Fatalf("could not find x84 rel32 branch near offset %d", 5+payloadLen+1)
	}

	displacement := int64(int32(binary.LittleEndian.Uint32(code[branchStart+3 : branchStart+7])))
	target := int64(branchEnd) + displacement
	if target < 0 || target+3 > int64(len(code)) {
		t.Fatalf("x84 branch target %d is outside output of %d bytes", target, len(code))
	}
	if got := code[target : target+3]; !bytes.Equal(got, []byte{0x5A, 0x51, 0x52}) {
		t.Fatalf("x84 branch target = %d points to %x, want x32 shim 5a5152", target, got)
	}
}

func TestMorphGenerationIsSafeConcurrently(t *testing.T) {
	loaderX86 := append([]byte(nil), LOADER_EXE_X86...)
	loaderX64 := append([]byte(nil), LOADER_EXE_X64...)
	payload := bytes.Repeat([]byte{0x3C}, 64)

	const (
		workers    = 24
		iterations = 20
	)
	var wg sync.WaitGroup
	errs := make(chan error, workers*iterations)
	for i := 0; i < workers; i++ {
		arch := X64
		if i%2 == 0 {
			arch = X84
		}
		wg.Add(1)
		go func(arch DonutArch) {
			defer wg.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				out, err := sandwich(arch, bytes.NewBuffer(append([]byte(nil), payload...)), true)
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

	if !bytes.Equal(LOADER_EXE_X86, loaderX86) {
		t.Fatal("morph generation modified the x86 loader global")
	}
	if !bytes.Equal(LOADER_EXE_X64, loaderX64) {
		t.Fatal("morph generation modified the x64 loader global")
	}
}

type failingRandomReader struct{}

func (failingRandomReader) Read([]byte) (int, error) {
	return 0, errors.New("test random source failure")
}

func TestMorphPropagatesRandomSourceFailure(t *testing.T) {
	oldReader := rand.Reader
	rand.Reader = failingRandomReader{}
	t.Cleanup(func() { rand.Reader = oldReader })

	config := DefaultConfig()
	config.Entropy = DONUT_ENTROPY_NONE
	config.Morph = true
	done := make(chan error, 1)
	go func() {
		_, err := ShellcodeFromBytes(bytes.NewBuffer([]byte{0x4D, 0x5A}), config)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ShellcodeFromBytes returned nil error after random source failure")
		}
		if !strings.Contains(err.Error(), "test random source failure") {
			t.Fatalf("ShellcodeFromBytes error = %q, want injected random source failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ShellcodeFromBytes did not return after random source failure")
	}
}

func TestMorphRejectsInvalidInputs(t *testing.T) {
	for _, isX64 := range []bool{false, true} {
		if _, _, err := encodeLoader(nil, isX64); err == nil {
			t.Fatalf("encodeLoader(nil, %t) returned nil error", isX64)
		}
	}
	if _, err := morphPreamble(DonutArch(99)); err == nil {
		t.Fatal("morphPreamble(invalid architecture) returned nil error")
	}
}

func TestArithmeticXORDecoderLayoutAndRoundTrip(t *testing.T) {
	payload := []byte{0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF, 0xC3}
	stub, encoded, key, err := arithmeticXOREncode(payload)
	if err != nil {
		t.Fatalf("arithmeticXOREncode: %v", err)
	}
	if len(stub) < 7 || !bytes.Equal(stub[:3], []byte{0x4C, 0x8D, 0x05}) {
		t.Fatalf("decoder does not begin with RIP-relative LEA: %x", stub)
	}
	leaOffset := int64(int32(binary.LittleEndian.Uint32(stub[3:7])))
	if leaOffset != int64(len(stub)-7) {
		t.Fatalf("LEA payload offset = %d, want %d", leaOffset, len(stub)-7)
	}
	assertEncodedRoundTrip(t, payload, encoded, key)

	stub32, encoded32, key32, err := arithmeticXOREncode32(payload)
	if err != nil {
		t.Fatalf("arithmeticXOREncode32: %v", err)
	}
	if len(stub32) < 15 || !bytes.Equal(stub32[:9], []byte{0x50, 0x51, 0x56, 0xE8, 0, 0, 0, 0, 0x5E}) {
		t.Fatalf("32-bit decoder has unexpected CALL/POP layout: %x", stub32)
	}
	assertEncodedRoundTrip(t, payload, encoded32, key32)
}

func assertEncodedRoundTrip(t *testing.T, payload, encoded []byte, key byte) {
	t.Helper()
	if key == 0 {
		t.Fatal("decoder selected a zero XOR key")
	}
	if len(encoded) != len(payload) || bytes.Equal(encoded, payload) {
		t.Fatalf("encoded payload has invalid shape: got %x", encoded)
	}

	decoded := make([]byte, len(encoded))
	for i, b := range encoded {
		decoded[i] = b ^ key
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("encoded round trip mismatch: got %x, want %x", decoded, payload)
	}
}

func TestInsertJunkPreservesCode(t *testing.T) {
	original := []byte{0xCC, 0xC3}
	for i := 0; i < 8; i++ {
		result, err := insertJunk(original)
		if err != nil {
			t.Fatalf("insertJunk: %v", err)
		}
		if len(result) < len(original) {
			t.Fatalf("iteration %d shortened code", i)
		}
		stripped := stripKnownNOPs(result)
		if !bytes.Equal(stripped, original) {
			t.Fatalf("iteration %d: got functional bytes %x, want %x", i, stripped, original)
		}
	}
}

func TestMorphRandomHelpersTerminateForDegenerateReaders(t *testing.T) {
	for _, value := range []byte{0x00, 0xFF} {
		t.Run(fmt.Sprintf("byte-%02x", value), func(t *testing.T) {
			replaceRandomReader(t, repeatingRandomReader(value))

			key, err := randNonZeroByte()
			if err == nil && key == 0 {
				t.Fatal("randNonZeroByte() returned zero")
			}

			original := []byte{0xCC, 0xC3}
			result, err := insertJunk(original)
			if err == nil && !bytes.Equal(stripKnownNOPs(result), original) {
				t.Fatalf("insertJunk() changed code: got %x, want %x", stripKnownNOPs(result), original)
			}
		})
	}
}

func stripKnownNOPs(code []byte) []byte {
	nops := [][]byte{
		{0x0F, 0x1F, 0x80, 0, 0, 0, 0},
		{0x66, 0x0F, 0x1F, 0x44, 0, 0},
		{0x0F, 0x1F, 0x44, 0, 0},
		{0x0F, 0x1F, 0x40, 0},
		{0x0F, 0x1F, 0},
		{0x66, 0x90},
		{0x90},
	}
	var out []byte
	for i := 0; i < len(code); {
		matched := false
		for _, nop := range nops {
			if i+len(nop) <= len(code) && bytes.Equal(code[i:i+len(nop)], nop) {
				i += len(nop)
				matched = true
				break
			}
		}
		if !matched {
			out = append(out, code[i])
			i++
		}
	}
	return out
}
