package donut

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestEntropyDefaultPICMatchesV11StageDecryption(t *testing.T) {
	config := DefaultConfig()
	config.Entropy = DONUT_ENTROPY_DEFAULT
	config.InstType = DONUT_INSTANCE_PIC
	config.ModuleData = bytes.NewBuffer([]byte("module-data"))

	instance, err := CreateInstance(config)
	if err != nil {
		t.Fatalf("CreateInstance() error = %v", err)
	}

	buf := append([]byte(nil), instance.Bytes()...)
	ctr := append([]byte(nil), buf[20:36]...)
	copy(buf[572:], Encrypt(buf[4:20], ctr, buf[572:]))

	got := Maru(buf[3116:], binary.LittleEndian.Uint64(buf[40:48]))
	want := binary.LittleEndian.Uint64(buf[3376:3384])
	if got != want {
		t.Fatalf("stage-emulated instance MAC = %#x, want %#x", got, want)
	}
}

func TestEntropyDefaultURLPreservesModuleCounter(t *testing.T) {
	module := []byte("module data longer than one Chaskey block")
	config := DefaultConfig()
	config.Entropy = DONUT_ENTROPY_DEFAULT
	config.InstType = DONUT_INSTANCE_URL
	config.ModuleName = "module.bin"
	config.ModuleData = bytes.NewBuffer(append([]byte(nil), module...))

	instance, err := CreateInstance(config)
	if err != nil {
		t.Fatalf("CreateInstance() error = %v", err)
	}

	buf := append([]byte(nil), instance.Bytes()...)
	ctr := append([]byte(nil), buf[20:36]...)
	copy(buf[572:], Encrypt(buf[4:20], ctr, buf[572:]))

	gotMAC := Maru(buf[3116:], binary.LittleEndian.Uint64(buf[40:48]))
	wantMAC := binary.LittleEndian.Uint64(buf[3376:3384])
	if gotMAC != wantMAC {
		t.Fatalf("stage-emulated URL instance MAC = %#x, want %#x", gotMAC, wantMAC)
	}

	moduleCtr := append([]byte(nil), buf[3400:3416]...)
	gotModule := Encrypt(buf[3384:3400], moduleCtr, config.ModuleData.Bytes())
	if !bytes.Equal(gotModule, module) {
		t.Fatalf("stage-emulated URL module = %q, want %q", gotModule, module)
	}
}
