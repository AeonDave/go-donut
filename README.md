# go-donut

Pure Go implementation of [Donut](https://github.com/TheWover/donut) shellcode generation. Converts PE files (.NET and native EXE/DLL), VBScript, and JScript into position-independent shellcode.

This fork updates the original [Binject/go-donut](https://github.com/Binject/go-donut) from donut v0.9.3 to **v1.0**, fixing .NET assembly support and adding ETW bypass capabilities.

## Changes from upstream

- **Loader stubs** updated to donut v1.0 (x64: 22KB → 13KB, x86: matching)
- **Struct layout** matches C donut v1.0 — 3 alignment padding fixes, OEP as uint32, new fields (Ntdll, Headers, ETW bypass, Decoy, split HTTP auth)
- **API imports** updated to 63 entries (adds HeapAlloc, NtCreateSection, InternetQueryDataAvailable, etc.)
- **Defaults** fixed: `Compress=0` remapped to `DONUT_COMPRESS_NONE` (1), `Headers` defaults to `DONUT_HEADERS_OVERWRITE` (1)
- **.NET support** verified working (Certify, Rubeus, RunasCs)

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
| `Entropy` | `int` | `1` = none, `2` = random names, `3` = random + encryption |
| `Bypass` | `int` | `1` = skip, `2` = abort on fail, `3` = continue on fail |
| `Compress` | `int` | `0`/`1` = none, `2` = aPLib |
| `ExitOpt` | `int` | `1` = ExitThread, `2` = ExitProcess, `3` = block |
| `Thread` | `uint32` | `1` = run EXE entrypoint as thread (hooks exit APIs) |
| `Parameters` | `string` | Command-line args for the payload |
| `Class` | `string` | .NET class name (required for .NET DLL) |
| `Method` | `string` | .NET method or DLL export name |

## Known limitations

- Instance encryption (`Entropy=3`) has a Chaskey cipher offset mismatch with v1.0 stubs. Use `Entropy=2` (random names without instance encryption). Payload encryption at the loader level (ChaCha20, etc.) is unaffected.
- Compression via RtlCompressBuffer (LZNT1/Xpress) is not implemented in Go. Use `Compress=0`.
- .NET tools that call `Environment.Exit` may produce truncated output due to stdout flush timing.

## License

BSD 3-Clause — same as [TheWover/donut](https://github.com/TheWover/donut).
