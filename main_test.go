package main

import "testing"

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
