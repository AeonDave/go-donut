# go-donut

Pure Go implementation of [Donut](https://github.com/TheWover/donut) shellcode generation. Converts PE files (.NET and native EXE/DLL), VBScript, and JScript into position-independent shellcode.

Based on [Binject/go-donut](https://github.com/Binject/go-donut), updated to the **Donut v1.1 runtime layout and x86/x64 loader stages**. The embedded x86 blob and x64 final stage are pinned by source-derived regression tests against the official v1.1 tag.

## Features

- **Donut v1.1 loader stages** — x86 core and stack-aligned x64 final stage
- **Struct layout** matches the Donut v1.1 ABI — alignment padding fixes, OEP as uint32, new fields (Ntdll, Headers, ETW bypass, Decoy, split HTTP auth)
- **API imports** — 63 entries (HeapAlloc, NtCreateSection, InternetQueryDataAvailable, etc.)
- **Polymorphic output** (`--morph`) — optional generation-time mutation that varies the shellcode layout while keeping the emitted loader RX-safe
- **.NET support** verified working (Certify, Rubeus, RunasCs)

## Polymorphic Mutation Engine (v1.1.4)

When `--morph` is enabled, the canonical loader core never appears in
plaintext in the artifact. Generation time per build:

1. the loader core is encrypted with a per-build scheme and key — rolling
   XOR, rolling ADD, or an MBA-expressed XOR whose decoder computes
   `a^b` as `(a & ~b) | (~a & b)` from raw bytes (no compiler sits in the
   path, so the identities can never be folded back to a plain `xor`);
2. a generation-time trampoline is emitted that resolves
   `VirtualAlloc`/`VirtualProtect`/`FlushInstructionCache` via a PEB walk,
   allocates a fresh RW page, decrypts the core into it, flips it RX, flushes
   the instruction cache, and transfers control with the original entry
   contract (registers, flags, and stack) fully restored via a balanced
   `push target; ret`;
3. keys are validated so no build ever leaks a plaintext byte at an identity
   position (the rolling-ADD `i≡0 mod 256` leak class is excluded by
   construction).

The emitted stage never writes to its own pages, so it remains valid under a
`PAGE_EXECUTE_READ` handoff (W^X). The corpus regression suite
(`donut/yara_corpus_test.go`) asserts that a selected exact-byte atom subset
from the catalogued families is absent from sampled morphed artifacts; it does
not run the complete public rules through a YARA engine. The loader core and
entropy-3 instance body are per-build ciphertext; the clear structured header,
stub machine code, and alignment padding remain. Entropy 3 is qualified for
PIC artifacts by stage emulation and runtime spot cells; URL mode has Go-side
counter-preservation coverage only.

| Technique | Description |
|-----------|-------------|
| **Core encryption** | Per-build scheme+key; ciphertext only in the artifact |
| **RX-safe trampoline** | PEB-resolve → alloc RW → decrypt → RX → FlushInstructionCache → balanced transfer |
| **X84 preamble substitution** | `sub eax,eax` / `and eax,0` — the canonical `xor eax,eax` form is deliberately excluded so the Rapid7 `{ 59 31 C0 48 0F }` atom cannot form |
| **NOP-equivalent padding** | Intel multi-byte NOPs in front of the trampoline (extra per-build variance) |

```go
config := donut.DefaultConfig()
config.Arch = donut.X64
config.Entropy = donut.DONUT_ENTROPY_DEFAULT // instance encryption (qualified)
config.Morph = true                            // core encryption + trampoline
config.Evade = donut.EvadeHwbp                 // patchless AMSI/WLDP/ETW stub
config.EvadeTargets = donut.EvadeAmsi            // AMSI only (recommended for .NET)
shellcode, err := donut.ShellcodeFromFile("payload.exe", config)
```

## Patchless Evasion (`--evade`)

The loader's built-in AMSI/WLDP patch is signatured into extinction
(Defender platform 1.419.240.0+ kills entry-point patches via kernel-event
memory scans; Elastic's 2025-10 rule kills the VirtualProtect/Write path).
`--evade <families>` replaces it with hardware-execution breakpoints (DR0–DR3) on
`AmsiScanBuffer`, `AmsiScanString`, `ntdll!NtTraceEvent`, and
`WldpIsClassInApprovedList`, plus a Vectored Exception Handler that rewrites
the faulting CONTEXT to simulate an immediate benign return through a real
`ret`/`ret imm16` gadget. The handler is designed for CET shadow-stack safety
and exact stdcall cleanup; these properties are structurally verified, not
runtime-invocation-tested. No code page is ever modified — the stage remains
RX-only. Per-build variation covers the hash family and seed, DR-slot
permutation, encoded module strings, decoder scheme, and NOP prefix. Family
selection is independent: AMSI is omitted when not listed. When evade is
active the instance is generated with the built-in patch disabled
(`Bypass=1`). Residual, documented surface:
`NtSetContextThread` ETWti on CrowdStrike-class sensors, VEH-chain
enumeration, single-step density.

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

### CLI — all flags

```text
go-donut -i <input> [options]

MODULE OPTIONS
  -n, --module <name>   Module name; random with entropy enabled (default: random)
  -u, --url <url>       HTTP server hosting the module (staged mode; omit for self-contained)
  -e, --entropy <1-3>   1 = plaintext instance, 2 = random names (default),
                        3 = random names + Chaskey instance encryption (recommended with --morph)

SHELLCODE OPTIONS
  -a, --arch <arch>     x32, x64, or x84 = dual 32+64 (default: x84)
  -b, --bypass <1-3>    AMSI/WLDP behaviour of the BUILT-IN patch (only when --evade is off):
                        1 = skip, 2 = abort on fail, 3 = continue on fail (default)
      --evade <mode>    Patchless evasion via hardware breakpoints + VEH (replaces the
                        built-in patch; instance Bypass is forced to 1):
                        off                  no evade stub (default; built-in patch per -b)
                        hwbp                 all families: AMSI + ETW + WLDP
                        amsi                 AMSI scan interception only (recommended for .NET)
                        etw                  user-mode ETW suppression only
                        wldp                 WLDP policy check only
                        comma lists allowed: --evade amsi,etw
                        AMSI is omitted when not listed
      --morph           Encrypt the loader core per build (XOR/ADD/MBA scheme + key) behind
                        an RX-safe trampoline; the canonical loader never appears in plaintext.
                        With entropy < 3 prints a warning: the instance stays plaintext.
  -o, --out <file>      Output file (default: loader.bin)
  -f, --format <1>      Output format: 1 = raw shellcode (default; only raw supported)
  -y, --oep <hex>       Original entry point offset (hex); 32-bit field
  -x, --exit <1-3>      1 = exit thread (default), 2 = exit process

FILE OPTIONS
  -c, --class <name>    .NET class (required for .NET DLL)
  -d, --domain <name>   .NET AppDomain; random with entropy enabled (default: random)
  -m, --method <name>   .NET method or DLL export
  -p, --params <str>    Parameter string (passed verbatim; not split)
  -w, --unicode         Pass params to unmanaged DLL function as UNICODE
  -r, --runtime <ver>   CLR runtime version; overrides auto-detection
  -t, --thread          Run unmanaged EXE entrypoint in a thread
  -z, --compress <1>    1 = none (default; compression unsupported)
  -i, --in <file>       Input: .NET EXE/DLL, native EXE/DLL, VBS, JS, XSL (required)
  -v, --verbose         Verbose generation output
```

### Common commands

```bash
# High-assurance configuration (.NET payload): encrypted instance + encrypted core + AMSI-only interception
go-donut -i payload.exe -a x64 -e 3 --morph --evade amsi -o loader.bin

# Dual-arch, full evasion stack
go-donut -i payload.exe -a x84 -e 3 --morph --evade hwbp -o loader.bin

# AMSI + user-mode ETW, no WLDP (fewer module loads)
go-donut -i payload.exe -a x64 -e 3 --morph --evade amsi,etw -o loader.bin

# Canonical donut v1.1 stages (with the fork's documented source-guided relocation patches)
go-donut -i payload.exe -a x64 -e 1 -o loader.bin
```

> `--evade etw` suppresses user-mode ETW on the loading thread only; kernel ETW-TI
> telemetry is out of scope by design. See Known limitations.

## Supported input types

| Type | Extension | Detection |
|------|-----------|-----------|
| .NET EXE | `.exe` | Auto (CLR metadata) |
| .NET DLL | `.dll` | Auto (CLR metadata) |
| Native EXE | `.exe` | Auto |
| Native DLL | `.dll` | Auto |
| VBScript | `.vbs` | Extension |
| JScript | `.js` | Extension |
| XSL | `.xsl` | Extension |

## Configuration

| Field | Type | Description |
|-------|------|-------------|
| `Arch` | `DonutArch` | `X32` (1), `X64` (2), `X84` (3 = dual) |
| `InstType` | `InstanceType` | `DONUT_INSTANCE_PIC` (1) or `DONUT_INSTANCE_URL` (2) |
| `Entropy` | `uint32` | `1` = none, `2` = random names (default), `3` = random names + instance encryption |
| `Bypass` | `int` | `1` = skip, `2` = abort on fail, `3` = continue on fail |
| `Compress` | `int` | `0` or `1` = none; compression modes `2`–`4` are unsupported |
| `Format` | `int` | `0` or `1` = raw shellcode; other output formats are unsupported |
| `ExitOpt` | `int` | `1` = ExitThread, `2` = ExitProcess, `3` = block |
| `Thread` | `uint32` | `1` = run EXE entrypoint as thread (hooks exit APIs) |
| `Morph` | `bool` | Encrypt the loader core per build and emit a runtime trampoline that decrypts it into fresh RW memory before changing that memory to RX |
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

The supported scope remains explicit: entropy `1`, `2`, and `3`, raw formats
`0` and `1`, and architectures `x32`, `x64`, and `x84` are supported.
Compression modes `2`–`4` and output formats `2`–`8` are rejected.

Runtime qualification covers relocatable PE fixtures. The x86 fixed-base,
no-relocation path is outside the qualification scope; its existing diagnostic
failure is not attributed to this patch, so no universal no-relocation support
claim is made.

## Known limitations

- `--evade etw` is user-mode, loading-thread scoped; kernel ETW-TI providers are
  unaffected (design boundary, see daybreak review B6). ETW slot persistence also
  generates single-step exception density proportional to event volume.

- Instance encryption (`Entropy=3`) is qualified for PIC artifacts with stage emulation and runtime spot cells. URL mode has Go-side counter-preservation coverage only; URL staging execution is not runtime-qualified.
- Compression via RtlCompressBuffer (LZNT1/Xpress) is not implemented in Go. The API and CLI accept only `Compress=0` or `Compress=1` and reject modes `2`–`4`.
- Output formatting is currently raw shellcode only. `Format=0` and `Format=1` are accepted for compatibility; the API and CLI reject base64, C, Ruby, Python, PowerShell, C#, and hex output modes.
- .NET tools that call `Environment.Exit` may produce truncated output due to stdout flush timing.

## License

BSD 3-Clause — same as [TheWover/donut](https://github.com/TheWover/donut).
