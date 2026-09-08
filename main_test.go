package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseOEP(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint32
		wantErr bool
	}{
		{name: "empty defaults to zero", input: "", want: 0},
		{name: "accepts max uint32", input: "FFFFFFFF", want: ^uint32(0)},
		{name: "rejects uint32 overflow", input: "100000000", wantErr: true},
		{name: "rejects invalid hexadecimal", input: "nope", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOEP(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("parseOEP() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseOEP() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("parseOEP() = %#x, want %#x", got, tt.want)
			}
		})
	}
}

func TestRunReturnsInputFileError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.exe")
	out := filepath.Join(t.TempDir(), "loader.bin")

	err := run([]string{"go-donut", "-i", missing, "-o", out})
	if err == nil {
		t.Fatal("run() error = nil, want missing input file error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("run() error = %v, want os.ErrNotExist", err)
	}
	if _, statErr := os.Stat(out); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("output file exists after failed generation: stat error = %v", statErr)
	}
}

func TestRunRejectsUnsupportedOptions(t *testing.T) {
	tests := []struct {
		name  string
		flag  string
		value string
		want  string
	}{
		{name: "entropy", flag: "-e", value: "3", want: "unsupported entropy 3"},
		{name: "compression", flag: "-z", value: "2", want: "unsupported compression 2"},
		{name: "format", flag: "-f", value: "2", want: "unsupported format 2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := run([]string{"go-donut", tt.flag, tt.value, "-i", "missing.exe"})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("run() error = %v, want substring %q", err, tt.want)
			}
		})
	}
}
