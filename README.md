# go-donut

AeonDave's Pure Go fork of [Donut](https://github.com/TheWover/donut) shellcode generation. Converts PE files (.NET and native EXE/DLL), VBScript, and JScript into position-independent shellcode.

This AeonDave fork updates the original [Binject/go-donut](https://github.com/Binject/go-donut) to the **Donut v1.1 runtime layout and canonical x86/x64 loader stages**, while retaining the Go API. The embedded x86 blob and x64 final stage are pinned by source-derived regression tests against the official v1.1 tag.

## Changes from upstream

- **Loader stages** use the canonical Donut v1.1 x86 core and stack-aligned x64 final stage
- **Struct layout** matches the Donut v1.1 ABI — 3 alignment padding fixes, OEP as uint32, new fields (Ntdll, Headers, ETW bypass, Decoy, split HTTP auth)
- **API imports** updated to 63 entries (adds HeapAlloc, NtCreateSection, InternetQueryDataAvailable, etc.)
- **Defaults** fixed: `Compress=0` remapped to `DONUT_COMPRESS_NONE` (1), `Headers` defaults to `DONUT_HEADERS_OVERWRITE` (1)
- **Donut v1.1 stages**: canonical x86 blob, x64 stack-aligned stage, architecture values, and 4,760-byte instance layout are regression-tested against the official v1.1 sources
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
| `Parameters` | `string` | One payload parameter string; it is not split by commas, semicolons, or shell parsing |
| `Class` | `string` | .NET class name (required for .NET DLL) |
| `Method` | `string` | .NET method or DLL export name |

## Known limitations

- Instance encryption (`Entropy=3`) is not qualified in this Go port because its Chaskey offsets do not yet match the embedded v1.1 stages. Use `Entropy=2`; unsupported behavior is documented rather than treated as implicit fallback.
- Compression via RtlCompressBuffer (LZNT1/Xpress) is not implemented in Go. Use `Compress=0`.
- .NET tools that call `Environment.Exit` may produce truncated output due to stdout flush timing.

## License

BSD 3-Clause — same as [TheWover/donut](https://github.com/TheWover/donut).
