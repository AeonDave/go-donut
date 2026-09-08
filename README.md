# go-donut

Pure Go implementation of [Donut](https://github.com/TheWover/donut) shellcode generation. Converts PE files (.NET and native EXE/DLL), VBScript, and JScript into position-independent shellcode.

Based on [Binject/go-donut](https://github.com/Binject/go-donut), updated to the **Donut v1.1 runtime layout and x86/x64 loader stages**. The embedded x86 blob and x64 final stage are pinned by source-derived regression tests against the official v1.1 tag.

## Features

- **Donut v1.1 loader stages** — x86 core and stack-aligned x64 final stage
- **Struct layout** matches the Donut v1.1 ABI — alignment padding fixes, OEP as uint32, new fields (Ntdll, Headers, ETW bypass, Decoy, split HTTP auth)
- **API imports** — 63 entries (HeapAlloc, NtCreateSection, InternetQueryDataAvailable, etc.)
- **Polymorphic output** (`--morph`) — optional generation-time mutation that varies the shellcode layout while keeping the emitted loader RX-safe
- **.NET support** verified working (Certify, Rubeus, RunasCs)

## Polymorphic Mutation Engine

When `--morph` is enabled, mutation happens during shellcode generation. The
output contains no runtime decoder and does not rewrite executable memory, so
the generated stage can be handed off as `PAGE_EXECUTE_READ` while preserving
W^X. Random choices usually produce different surrounding bytes and hashes for
the same input; diversity is probabilistic.

| Technique | Description |
|-----------|-------------|
| **NOP-equivalent padding** | Generation prefixes each selected loader block with Intel-defined NOP encodings after any required architecture preamble. They have no architectural side effects and never modify code at runtime. |
| **X84 preamble substitution** | In dual-architecture mode, the zeroing instruction is selected from `xor eax,eax`, `sub eax,eax`, and `and eax,0`; the mode-switch branch displacement is regenerated for the resulting layout. |

The canonical Donut v1.1 loader body remains present in the output. Morph
changes the surrounding padding and, for X84, the equivalent dispatch
preamble; it does not transform or conceal the loader body. This gives static
layout diversity with a larger or otherwise different wrapper, while retaining
the original loader ABI and entry contracts.

```go
config := donut.DefaultConfig()
config.Arch = donut.X64
config.Entropy = donut.DONUT_ENTROPY_RANDOM
config.Morph = true // enable generation-time, RX-safe mutation
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
| `InstType` | `InstanceType` | `DONUT_INSTANCE_PIC` (1) or `DONUT_INSTANCE_URL` (2) |
| `Entropy` | `uint32` | `1` = none, `2` = random names (default) |
| `Bypass` | `int` | `1` = skip, `2` = abort on fail, `3` = continue on fail |
| `Compress` | `int` | `0` or `1` = none; compression modes `2`–`4` are unsupported |
| `Format` | `int` | `0` or `1` = raw shellcode; other output formats are unsupported |
| `ExitOpt` | `int` | `1` = ExitThread, `2` = ExitProcess, `3` = block |
| `Thread` | `uint32` | `1` = run EXE entrypoint as thread (hooks exit APIs) |
| `Morph` | `bool` | Enable generation-time static mutation; no runtime decoder is emitted |
| `Parameters` | `string` | One payload parameter string; it is not split by commas, semicolons, or shell parsing |
| `Class` | `string` | .NET class name (required for .NET DLL) |
| `Method` | `string` | .NET method or DLL export name |

## v1.1.3 compared with Donut v1.1

Version 1.1.3 includes the published v1.1.2 changes plus the post-release
RX-safe Morph fix. It preserves the Donut v1.1 instance ABI and layout. The
comparison with Donut v1.1 applies to the functions verified in this repository
and does not claim feature parity with the C tool.

- The Go port uses the v1.1 loader stages with a source-guided fix for the
  inherited remap path: it requests the original mapped base for the second
  view and returns on mapping failure.
- In v1.1.2, `--morph` used a runtime XOR decoder that rewrote its loader in
  place. An Ashura handoff that marked the stage `PAGE_EXECUTE_READ` could
  therefore fault. v1.1.3 removes the runtime decoder and self-writes:
  `--morph` now applies generation-time NOP padding and X84 preamble
  substitutions for x86 (`x32`), x64 (`x64`), and the dual target (`x84`). The
  canonical v1.1 loader body remains in the generated stage.
- Random generation uses `crypto/rand` with propagated errors.
- The CLI returns non-zero status on errors and validates architecture, entropy,
  compression, format, and OEP before generating output.
- URL staging validates configuration before download, handles explicit or
  generated module names, and propagates download and write errors.
- Existing public functions remain available; new behavior is exposed through
  `DonutConfig.Morph` and `--morph`.

Runtime qualification for the generation-time Morph path is complete for the
tested relocatable fixtures. The generator was rebuilt from the current source
tree and run under GNU GDB 16.3 with hidden, serial processes. The RX harness
copied each generated loader into `PAGE_READWRITE`, changed it to
`PAGE_EXECUTE_READ`, flushed the instruction cache, and only then started the
loader thread. All 16 cases passed: X32/x86, X64/x64, X84/x86, and X84/x64,
each with canonical and Morph output at entropy 1 and 2. Every generator and
GDB run exited 0, emitted the exact marker, reached both harness checkpoints,
and recorded no exception, timeout, or residual test process. GDB also hit the
`before_shellcode`, `after_shellcode`, and `child_result` breakpoints in every
case; each breakpoint command emitted a parseable token and auto-continued.

The current Go gate set covers 58 tests. Go 1.27.1 `go test -race ./...` is
green. Updated staticcheck on Go 1.27.1 and govulncheck are clean. Under Go
1.16, `go test ./...`, `go vet ./...`, and `go build ./...` are green. Go 1.16
race is not qualified because of a pre-existing linker limitation.

The public API remains compatible: `DonutConfig.Morph` and `--morph` keep their
existing interfaces, `Sandwich` keeps its two-argument signature, and the
serialized Donut v1.1 instance ABI is unchanged. Consumers should use the
returned shellcode length rather than assuming a fixed wrapper size because
generation-time padding can change it.

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
