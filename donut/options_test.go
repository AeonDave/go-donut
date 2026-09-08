package donut

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfigUsesSupportedOptions(t *testing.T) {
	config := DefaultConfig()

	if config.Entropy != DONUT_ENTROPY_RANDOM {
		t.Fatalf("DefaultConfig().Entropy = %d, want %d", config.Entropy, DONUT_ENTROPY_RANDOM)
	}
	if config.Compress != 1 {
		t.Fatalf("DefaultConfig().Compress = %d, want 1", config.Compress)
	}
	if config.Format != 1 {
		t.Fatalf("DefaultConfig().Format = %d, want 1", config.Format)
	}
}

func TestShellcodeFromBytesRejectsUnsupportedOptions(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DonutConfig)
		want   string
	}{
		{name: "encrypted entropy", mutate: func(c *DonutConfig) { c.Entropy = DONUT_ENTROPY_DEFAULT }, want: "unsupported entropy 3"},
		{name: "compression", mutate: func(c *DonutConfig) { c.Compress = 2 }, want: "unsupported compression 2"},
		{name: "base64 format", mutate: func(c *DonutConfig) { c.Format = 2 }, want: "unsupported format 2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			tt.mutate(config)

			_, err := ShellcodeFromBytes(bytes.NewBuffer([]byte("payload")), config)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ShellcodeFromBytes() error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestShellcodeFromBytesAcceptsRawCompatibilityValues(t *testing.T) {
	config := DefaultConfig()
	config.Arch = X64
	config.Entropy = DONUT_ENTROPY_NONE
	config.Compress = 0
	config.Format = 0

	if _, err := ShellcodeFromBytes(bytes.NewBuffer([]byte("payload")), config); err != nil {
		t.Fatalf("ShellcodeFromBytes() with raw compatibility values returned error: %v", err)
	}
}

func TestShellcodeFromFileRejectsUnsupportedOptionsBeforeReading(t *testing.T) {
	config := DefaultConfig()
	config.Format = 8
	missing := filepath.Join(t.TempDir(), "missing.exe")

	_, err := ShellcodeFromFile(missing, config)
	if err == nil || !strings.Contains(err.Error(), "unsupported format 8") {
		t.Fatalf("ShellcodeFromFile() error = %v, want unsupported format error", err)
	}
}

func TestCreateModuleAndCreateInstanceRejectUnsupportedOptions(t *testing.T) {
	for _, option := range []struct {
		name   string
		mutate func(*DonutConfig)
		want   string
	}{
		{name: "entropy", mutate: func(c *DonutConfig) { c.Entropy = DONUT_ENTROPY_DEFAULT }, want: "unsupported entropy 3"},
		{name: "compression", mutate: func(c *DonutConfig) { c.Compress = 2 }, want: "unsupported compression 2"},
		{name: "format", mutate: func(c *DonutConfig) { c.Format = 2 }, want: "unsupported format 2"},
	} {
		t.Run(option.name+" module", func(t *testing.T) {
			config := DefaultConfig()
			option.mutate(config)
			err := CreateModule(config, bytes.NewBuffer([]byte("payload")))
			if err == nil || !strings.Contains(err.Error(), option.want) {
				t.Fatalf("CreateModule() error = %v, want substring %q", err, option.want)
			}
		})
		t.Run(option.name+" instance", func(t *testing.T) {
			config := DefaultConfig()
			option.mutate(config)
			config.ModuleData = bytes.NewBuffer([]byte("module"))
			_, err := CreateInstance(config)
			if err == nil || !strings.Contains(err.Error(), option.want) {
				t.Fatalf("CreateInstance() error = %v, want substring %q", err, option.want)
			}
		})
	}
}
