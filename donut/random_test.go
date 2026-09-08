package donut

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
)

type randomSourceFailure struct{}

func (randomSourceFailure) Read([]byte) (int, error) {
	return 0, errRandomSourceFailure
}

var errRandomSourceFailure = errors.New("injected random source failure")

func replaceRandomReader(t *testing.T, reader interface{ Read([]byte) (int, error) }) {
	t.Helper()
	previous := rand.Reader
	rand.Reader = reader
	t.Cleanup(func() { rand.Reader = previous })
}

func TestRandomStringWithErrorValidatesLengthAndSource(t *testing.T) {
	if got, err := RandomStringWithError(-1); err == nil || got != "" {
		t.Fatalf("RandomStringWithError(-1) = %q, %v; want empty string and error", got, err)
	}

	replaceRandomReader(t, randomSourceFailure{})
	got, err := RandomStringWithError(1)
	if !errors.Is(err, errRandomSourceFailure) {
		t.Fatalf("RandomStringWithError() error = %v; want injected source error", err)
	}
	if got != "" {
		t.Fatalf("RandomStringWithError() result = %q after source failure; want empty string", got)
	}
}

func TestLegacyRandomStringHandlesInvalidInputAndSourceFailure(t *testing.T) {
	if got := RandomString(-1); got != "" {
		t.Fatalf("RandomString(-1) = %q; want empty string", got)
	}

	replaceRandomReader(t, randomSourceFailure{})
	if got := RandomString(1); got != "" {
		t.Fatalf("RandomString() = %q after source failure; want empty string", got)
	}
}

func TestGenerateRandomBytesRejectsNegativeCount(t *testing.T) {
	got, err := GenerateRandomBytes(-1)
	if err == nil || got != nil {
		t.Fatalf("GenerateRandomBytes(-1) = %v, %v; want nil and error", got, err)
	}
}

func TestCreateModulePropagatesRandomSourceFailure(t *testing.T) {
	replaceRandomReader(t, randomSourceFailure{})
	config := DefaultConfig()
	config.Type = DONUT_MODULE_NET_DLL
	config.Entropy = DONUT_ENTROPY_RANDOM

	err := CreateModule(config, bytes.NewBuffer([]byte("module")))
	if !errors.Is(err, errRandomSourceFailure) {
		t.Fatalf("CreateModule() error = %v; want injected source error", err)
	}
	if !strings.Contains(err.Error(), "generate module domain") {
		t.Fatalf("CreateModule() error = %q; want domain context", err)
	}
}

func TestCreateInstancePropagatesRandomSourceFailure(t *testing.T) {
	replaceRandomReader(t, randomSourceFailure{})
	config := DefaultConfig()
	config.Entropy = DONUT_ENTROPY_RANDOM
	config.InstType = DONUT_INSTANCE_URL
	config.ModuleData = bytes.NewBuffer([]byte("module"))

	_, err := CreateInstance(config)
	if !errors.Is(err, errRandomSourceFailure) {
		t.Fatalf("CreateInstance() error = %v; want injected source error", err)
	}
	if !strings.Contains(err.Error(), "generate module name") {
		t.Fatalf("CreateInstance() error = %q; want module-name context", err)
	}
}

type repeatingRandomReader byte

func (r repeatingRandomReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

func TestCreateInstanceURLModuleNameHandling(t *testing.T) {
	tests := []struct {
		name       string
		entropy    uint32
		moduleName string
		want       string
		reader     io.Reader
	}{
		{name: "empty random name", entropy: DONUT_ENTROPY_RANDOM, want: "aaaaaaaa", reader: repeatingRandomReader(0)},
		{name: "empty no entropy fallback", entropy: DONUT_ENTROPY_NONE, want: "AAAAAAAA"},
		{name: "explicit random name preserved", entropy: DONUT_ENTROPY_RANDOM, moduleName: "keep.bin", want: "keep.bin"},
		{name: "explicit no entropy name preserved", entropy: DONUT_ENTROPY_NONE, moduleName: "keep.bin", want: "keep.bin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.reader != nil {
				replaceRandomReader(t, tt.reader)
			}
			config := DefaultConfig()
			config.Entropy = tt.entropy
			config.InstType = DONUT_INSTANCE_URL
			config.URL = "https://example.invalid"
			config.ModuleName = tt.moduleName
			config.ModuleData = bytes.NewBuffer([]byte("module"))

			if _, err := CreateInstance(config); err != nil {
				t.Fatalf("CreateInstance() error = %v", err)
			}
			if config.ModuleName != tt.want {
				t.Fatalf("config.ModuleName = %q, want %q", config.ModuleName, tt.want)
			}
		})
	}
}
