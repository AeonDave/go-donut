# go-donut

Pure Go implementation of [Donut](https://github.com/TheWover/donut) shellcode generation. Converts PE files (.NET and native EXE/DLL), VBScript, and JScript into position-independent shellcode.

Based on [Binject/go-donut](https://github.com/Binject/go-donut), updated to the **Donut v1.1 runtime layout and x86/x64 loader stages**. The embedded x86 blob and x64 final stage are pinned by source-derived regression tests against the official v1.1 tag.

## Features

- **Donut v1.1 loader stages** — x86 core and stack-aligned x64 final stage
- **Struct layout** matches the Donut v1.1 ABI — alignment padding fixes, OEP as uint32, new fields (Ntdll, Headers, ETW bypass, Decoy, split HTTP auth)
- **API imports** — 63 entries (HeapAlloc, NtCreateSection, InternetQueryDataAvailable, etc.)
- **Polymorphic output** (`--morph`) — optional build-time mutation engine that varies the generated loader bytes between successful generations
- **.NET support** verified working (Certify, Rubeus, RunasCs)

## Polymorphic Mutation Engine

When `--morph` is enabled, each successful shellcode generation samples a non-zero XOR key, an arithmetic decoder form, and NOP padding for the loader. These random choices usually produce different loader bytes and hashes for the same input; diversity is probabilistic and applies to the generated loader region.

| Technique | Description |
|-----------|-------------|
| **Arithmetic XOR encoding** | Loader stub is XOR-encoded with a random key, but the decoder uses arithmetic equivalents (`(A & ~B) \| (~A & B)`) instead of a direct XOR instruction |
| **Preamble substitution** | Fixed preamble instructions are replaced with semantically equivalent alternatives (`xor eax,eax` ↔ `sub eax,eax` ↔ `and eax,0`) |
| **Junk insertion** | Intel-defined NOP-equivalent instruction sequences are inserted before the decoder stub |

The mutation engine is covered by structural tests and decoder encode/decode round-trip tests. The test suite does not execute generated shellcode, so runtime equivalence and resistance to a particular static signature are not guaranteed by this project.

```go
config := donut.DefaultConfig()
config.Arch = donut.X64
config.Entropy = donut.DONUT_ENTROPY_RANDOM
config.Morph = true // enable polymorphic output
shellcode, err := donut.ShellcodeFromFile("payload.exe", config)
```

## Usage

```go
package main

import (
    "fmt"
    "github.com/AeonDave/go-donut/donut"
)

func main() {
    config := &donut.DonutConfig{
        Arch:     donut.X64,
        InstType: donut.DONUT_INSTANCE_PIC,
        Format:   1,
        Entropy:  donut.DONUT_ENTROPY_RANDOM,
        Bypass:   3,
        Compress: 0,
        ExitOpt:  2,
    }

    shellcode, err := donut.ShellcodeFromFile("payload.exe", config)
    if err != nil {
        panic(err)
    }
    fmt.Printf("shellcode: %d bytes\n", shellcode.Len())
}
```

### CLI

```bash
go-donut -i payload.exe -a x64 -e 2 -o loader.bin --morph
```

## Supported input types

| Type | Extension | Detection |
|------|-----------|-----------|
| .NET EXE | `.exe` | Auto (CLR metadata) |
| .NET DLL | `.dll` | Auto (CLR metadata) |
| Native EXE | `.exe` | Auto |
| Native DLL | `.dll` | Auto |
| VBScript | `.vbs` | Extension |
| JScript | `.js` | Extension |

## Configuration

| Field | Type | Description |
|-------|------|-------------|
| `Arch` | `DonutArch` | `X32` (1), `X64` (2), `X84` (3 = dual) |
| `InstType` | `int` | `DONUT_INSTANCE_PIC` (1) or `DONUT_INSTANCE_URL` (2) |
| `Entropy` | `int` | `1` = none, `2` = random names (default) |
| `Bypass` | `int` | `1` = skip, `2` = abort on fail, `3` = continue on fail |
| `Compress` | `int` | `0` or `1` = none; compression modes `2`–`4` are unsupported |
| `Format` | `int` | `0` or `1` = raw shellcode; other output formats are unsupported |
| `ExitOpt` | `int` | `1` = ExitThread, `2` = ExitProcess, `3` = block |
| `Thread` | `uint32` | `1` = run EXE entrypoint as thread (hooks exit APIs) |
| `Morph` | `bool` | Enable polymorphic mutation of loader stub |
| `Parameters` | `string` | One payload parameter string; it is not split by commas, semicolons, or shell parsing |
| `Class` | `string` | .NET class name (required for .NET DLL) |
| `Method` | `string` | .NET method or DLL export name |

## v1.1.2 compared with Donut v1.1

Version 1.1.2 updates the Go port while preserving the Donut v1.1 instance ABI
and layout. The comparison with Donut v1.1 applies to the functions verified in
this repository and does not claim feature parity with the C tool.

- The Go port uses the v1.1 loader stages with a source-guided fix for the
  inherited remap path: it requests the original mapped base for the second
  view and returns on mapping failure.
- `--morph` adds verified mutations for x86 (`x32`), x64 (`x64`), and the dual
  target (`x84`) while preserving the public `Sandwich` signature.
- Random generation uses `crypto/rand` with propagated errors; invalid counts,
  failing random sources, and concurrent access are covered by tests.
- The CLI returns non-zero status on errors and validates architecture, entropy,
  compression, format, and OEP before generating output.
- URL staging validates configuration before download, handles explicit or
  generated module names, and propagates download and write errors.
- Existing public functions remain available; new behavior is exposed through
  `DonutConfig.Morph` and `--morph`.

Runtime qualification used ABI-correct relocatable PE payloads, verified
harnesses, GDB 16.3 hidden/batch mode, serial execution, a marker, and three
breakpoints. Each case exited 0 with the marker and breakpoints present and no
exception:

| Target and payload | Entropy | Default loader + morph | Result |
|---|---|---|---|
| x32 / x86 | 1 and 2 | both | PASS (4/4) |
| x64 / x64 | 1 and 2 | both | PASS (4/4) |
| x84 / x86 | 1 and 2 | both | PASS (4/4) |
| x84 / x64 | 1 and 2 | both | PASS (4/4) |

The available Go gates are green for `go test ./...` (58 tests),
`go test -race ./...` (58 tests), `go test -count=20 ./...` (1160 tests),
`go vet ./...`, and `go build ./...`.

The supported scope remains explicit: entropy `3`, compression `2`–`4`, and
output formats `2`–`8` are rejected. Raw formats `0` and `1`, entropy `1` and
`2`, and architectures `x32`, `x64`, and `x84` are supported.

Runtime qualification covers relocatable PE fixtures. The x86 fixed-base,
no-relocation path is outside the qualification scope; its existing diagnostic
failure is not attributed to this patch, so no universal no-relocation support
claim is made.

## Known limitations

- Instance encryption (`Entropy=3`) is not qualified in this Go port because its Chaskey offsets do not yet match the embedded v1.1 stages. The API and CLI reject it with an explicit error; use `Entropy=2`.
- Compression via RtlCompressBuffer (LZNT1/Xpress) is not implemented in Go. The API and CLI accept only `Compress=0` or `Compress=1` and reject modes `2`–`4`.
- Output formatting is currently raw shellcode only. `Format=0` and `Format=1` are accepted for compatibility; the API and CLI reject base64, C, Ruby, Python, PowerShell, C#, and hex output modes.
- .NET tools that call `Environment.Exit` may produce truncated output due to stdout flush timing.

## License

BSD 3-Clause — same as [TheWover/donut](https://github.com/TheWover/donut).
