<p align="center">
  <strong>gamayun</strong><br>
  <em>A Binary Ninja Lumina client for dazhbog with IDA-parity CalcRel hashing, metadata decoding, and safe application workflows.</em>
</p>

<p align="center">
  <code>C++20</code> &middot; <code>Binary Ninja UI</code> &middot; <code>Qt6</code> &middot; <code>Lumina v6</code> &middot; <code>CalcRel parity</code> &middot; <code>read-only client</code>
</p>

---

**Gamayun** is a native Binary Ninja plugin that speaks the Lumina protocol, computes Lumina-compatible function hashes inside Binary Ninja, queries a `dazhbog` or IDA-compatible Lumina server, parses returned metadata, and applies that metadata back into the active analysis database.

The point is not merely to "talk Lumina." The point is to make Binary Ninja behave like a serious Lumina client: hash functions the way IDA expects, avoid querying obviously unreliable functions, decode returned metadata natively, and provide an interactive workflow for inspecting and applying names, comments, types, and frame information.

```bash
# Build and install the plugin
make install

# Then open Binary Ninja, show the Gamayun widget,
# pull metadata, inspect it, and apply it.
```

---

<h3 align="center">Default dazhbog endpoint</h3>

<div align="center">These values are already the plugin defaults</div>

<h3 align="center"><i>host</i>: ida.int.mov<br/><i>port</i>: 1234</h3>

<div align="center">TLS enabled by default &middot; certificate verification disabled by default</div>

---

## At a glance

| Area | What it does |
|------|---------------|
| **CalcRel engine** | Computes IDA-style `MD5(normalized_bytes || mask_bytes)` signatures from Binary Ninja analysis |
| **Protocol client** | Implements Lumina `HELLO` + `PULL` over plaintext or TLS, currently targeting protocol version `6` |
| **Metadata pipeline** | Parses Lumina metadata blobs into structured comments, types, frame data, stack points, and operand representations |
| **Apply engine** | Applies names, comments, types, stack variables, and diagnostic tags back into Binary Ninja |
| **UI workflow** | Provides a `Gamayun` widget for pull-selected, pull-all, inspect, log, apply, and batch-diff flows |
| **Safety filter** | Skips PLT stubs, CRT functions, and likely ARM64 split-tail layout mismatches before querying the server |
| **Debug tooling** | Emits detailed CalcRel dumps and ships comparison/verification scripts for parity work against IDA |

## Why Gamayun exists

Binary Ninja has strong analysis and UI primitives, but it does not ship with a first-class Lumina client for `dazhbog`-style workflows. The hard part is not only sending packets. The hard part is everything around that:

- getting CalcRel hashing close enough to IDA that lookups are actually useful
- understanding returned metadata instead of treating it as an opaque blob
- applying remote data back into Binary Ninja in a way that feels native
- refusing to query functions that are likely to mismatch because Binary Ninja and IDA disagree about function layout

Gamayun exists to close that gap.

It gives Binary Ninja a practical, inspectable, native Lumina client with a bias toward correctness and operator visibility rather than "best effort" lookup spam.

## What it does

Gamayun gives Binary Ninja a full read-side Lumina workflow:

- **Computes Lumina-compatible function keys** using a dedicated CalcRel masking engine in `src/analysis/`
- **Connects to `dazhbog` or other Lumina-compatible servers** using a Qt socket client in `src/lumina/client.*`
- **Identifies itself as a read-only Binary Ninja client** using Binary Ninja version/build data plus a fixed sentinel license identifier
- **Parses returned metadata natively** instead of leaving it as raw bytes
- **Lets you inspect and diff metadata before applying it** through the Gamayun widget and batch diff dialog
- **Applies useful metadata back into Binary Ninja** including names, comments, type information, stack variables, and tags for partially-decoded data
- **Supports automatic post-analysis queries** when enabled in settings

## Feature set

### CalcRel and matching

- **IDA-style hash shape** - computes `MD5(normalized_bytes || mask_bytes)` rather than hashing raw bytes directly
- **Architecture-aware masking** - dedicated masking logic for x86/x64, ARM/Thumb, and AArch64
- **Chunk-aware control-flow handling** - x86/x64 branch masking follows function chunk boundaries instead of only whole-function bounds
- **AArch64 improvements** - tracks page-relative state, branch forms, and Binary Ninja register-value fallbacks to reduce parity misses on ARM64
- **Full debug dump support** - writes per-function dumps to `/tmp/lumina_debug` or `LUMINA_DEBUG_DIR`

### Lumina client and metadata handling

- **Protocol version `6`** support via `src/lumina/protocol.*`
- **`HELLO` + `PULL` flow** implemented end-to-end in `src/lumina/client.*`
- **TLS or plaintext transport** selected from Binary Ninja settings
- **Read-only sentinel license ID** baked into `src/lumina/codec.h` so no external IDA license file is needed for the client identity path used here
- **Native metadata parser** in `src/lumina/metadata.*` for Lumina chunks such as comments, frame descriptions, stack points, and operand representations
- **Native type decoder** in `src/lumina/type_decoder.*` for rendering IDA type payloads into declaration strings Binary Ninja can try to parse

### Binary Ninja UI workflow

The `Gamayun` widget in `src/ui/gamayun/` gives you a practical analyst-facing flow:

- **Refresh** - rebuild the visible function list from the current view
- **Pull** - query the server for selected functions only
- **Pull All** - query the server for all eligible functions in the binary
- **Inspect** - open a detailed metadata inspector for cached results
- **Log** - dump cached metadata to the Binary Ninja log
- **Apply** - apply pulled metadata to selected functions
- **Apply All** - apply cached metadata across the binary
- **Batch Diff & Apply** - preview comment differences before applying them

Clicking a row also computes and logs that function's CalcRel hash for quick triage.

### Metadata application

The apply layer in `src/lumina/apply.*` is where Gamayun stops being a packet client and becomes a real integration. It can:

- rename functions from remote names
- apply function comments and repeatable comments
- decode and apply function type information when Binary Ninja accepts the declaration
- reconstruct stack variables from Lumina frame metadata when offsets and types can be recovered
- apply address comments reconstructed from instruction comment chunks
- attach diagnostic tags when type/frame/comment data exists but cannot be applied cleanly

When a piece of Lumina data cannot be represented exactly in Binary Ninja, Gamayun tries to preserve it as tags rather than silently dropping it.

### Reliability filtering

The plugin is intentionally conservative about querying bad candidates.

`lumina::shouldSkipPull()` in `src/analysis/pattern_gen.*` currently skips:

- **PLT stubs** in `.plt`, `.plt.got`, and `.plt.sec`
- **known CRT/runtime functions** such as `_init`, `_fini`, and `__libc_csu_init`
- **likely AArch64 split-tail layout mismatches** where Binary Ninja appears to stop a function early but nearby executable non-call branches suggest IDA may treat the tail differently

That last filter matters in practice: it prevents sending hashes that are likely to be structurally wrong even when the masking rules themselves are correct.

---

## Architecture

At a high level, Gamayun is a five-stage pipeline:

```text
Binary Ninja analysis
        |
        v
CalcRel engine (src/analysis/)
        |
        +--> reliability filter
        |
        v
Lumina HELLO + PULL client (src/lumina/client.* / protocol.*)
        |
        v
dazhbog / Lumina server
        |
        v
metadata parser + type decoder (src/lumina/metadata.* / type_decoder.*)
        |
        v
apply engine (src/lumina/apply.*)
        |
        v
Gamayun UI + Binary Ninja database updates (src/ui/gamayun/)
```

### Request flow

1. Binary Ninja finishes or advances analysis.
2. Gamayun computes CalcRel hashes for selected or eligible functions.
3. The reliability filter excludes functions that are probably unsafe to query.
4. The Lumina client sends `HELLO`, then `PULL`.
5. Returned metadata is decoded into structured C++ models.
6. The analyst can inspect it, log it, batch-diff it, or apply it directly.

### Read-only client identity

Gamayun currently behaves as a **read-only client**:

- it builds a Binary Ninja-flavored client key from the Binary Ninja version, build ID, and ABI version
- it uses a sentinel license ID of `FF FF FF FF 00 00`
- it focuses on `HELLO` + `PULL` workflows rather than full upload/delete/history parity

This makes it a clean client for `dazhbog` deployments without depending on local IDA license material.

---

## Repository map

- `src/plugin/` - plugin bootstrap, Binary Ninja registration, analysis-complete callback, and auto-query path
- `src/ui/gamayun/` - the main widget, table model, and table view
- `src/ui/dialogs/` - batch diff/apply dialog
- `src/lumina/` - protocol structs, socket client, session wiring, metadata parser, type decoder, apply engine, and settings
- `src/analysis/` - CalcRel masking and function-hash generation
- `src/debug/` - filesystem-backed debug dump helpers
- `tools/compare/` - maintained comparison helpers for plugin-vs-IDA analysis
- `tools/verify/` - maintained corpus verification scripts

## Build requirements

- CMake 3.15+
- a C++20-capable compiler
- Binary Ninja with UI development headers from `binaryninja-api/`
- Qt6 (`Core`, `Gui`, `Widgets`, `Network`)
- Capstone

The repository already includes a `Makefile` that wraps the common build/install flow and a `CMakeLists.txt` for direct use.

## Building

### With the Makefile

```bash
# Build
make build

# Install into your Binary Ninja plugins directory
make install
```

Useful targets:

```bash
make info
make uninstall
make rebuild
make distclean
```

`make install` intentionally refuses to run while Binary Ninja is open, because native Qt UI plugins are not safe to hot-reload.

### With CMake directly

```bash
cmake -S . -B build \
  -DBN_ALLOW_STUBS=ON \
  -DBN_INSTALL_DIR="/Applications/Binary Ninja.app" \
  -DQT6_ROOT_PATH="/path/to/Qt6"

cmake --build build --parallel
```

Build output lands in:

- `build/out/bin/libgamayun.dylib` on macOS
- `build/out/bin/libgamayun.so` on Linux

## Installation

The default plugin locations are:

- macOS: `~/Library/Application Support/Binary Ninja/plugins/`
- Linux: `~/.binaryninja/plugins/`

After copying the built library into the plugins directory, restart Binary Ninja and open the `Gamayun` widget from the UI.

---

## Using Gamayun

### Typical workflow

1. Open a binary in Binary Ninja.
2. Let initial analysis complete.
3. Open the `Gamayun` widget.
4. Use **Pull** or **Pull All** to query the server.
5. Use **Inspect** or **Log** to review returned metadata.
6. Use **Apply**, **Apply All**, or **Batch Diff & Apply** to merge the results into your database.

If `lumina.autoQueryOnAnalysis` is enabled, Gamayun will query automatically after Binary Ninja finishes initial analysis.

### What gets applied

Depending on what the server returns and what Binary Ninja can represent, the plugin may apply:

- function names
- function comments
- repeatable comments merged into the local comment view
- function signatures decoded from Lumina type info
- stack variables recovered from frame descriptions
- address comments reconstructed from instruction metadata
- tags describing operand representations, stack points, parse issues, or partial application failures

### What gets skipped

Gamayun will not blindly query every function. It skips known-bad or low-value cases such as PLT stubs and suspicious ARM64 split-tail mismatches, because sending bad hashes only creates misleading results.

---

## Configuration

Gamayun registers a `lumina` settings group in Binary Ninja.

| Setting | Default | Meaning |
|--------|---------|---------|
| `lumina.server.host` | `ida.int.mov` | Lumina / dazhbog server hostname |
| `lumina.server.port` | `1234` | Server port |
| `lumina.server.useTls` | `true` | Whether to use TLS |
| `lumina.server.verifyTls` | `false` | Whether to verify the TLS certificate |
| `lumina.autoQueryOnAnalysis` | `false` | Whether to query automatically after initial analysis |
| `lumina.timeout` | `10000` | Connection timeout in milliseconds |

### Environment overrides

These are useful during development or when testing against multiple servers:

| Variable | Purpose |
|----------|---------|
| `BN_LUMINA_HOST` | Override the configured server hostname |
| `BN_LUMINA_PORT` | Override the configured server port |
| `LUMINA_DEBUG` | Enable extra CalcRel and pull debug behavior |
| `LUMINA_DEBUG_META` | Enable extra metadata logging |
| `LUMINA_DUMP_BYTES` | Dump raw/normalized/mask buffers for deeper parity work |
| `LUMINA_DEBUG_DIR` | Override the debug dump directory (defaults to `/tmp/lumina_debug`) |

---

## Debugging and validation

Gamayun is built for parity work, not only day-to-day use. The repository includes maintained scripts for comparing Binary Ninja output against IDA truth data.

### Debug dump location

By default, debug output goes to:

```text
/tmp/lumina_debug
```

That directory can contain per-function dumps, request snapshots, and metadata summaries depending on which debug flags are enabled.

### Maintained tools

```bash
python3 tools/compare/compare_hashes.py --push /path/to/push_parsed.txt --meta /tmp/lumina_debug/meta.log
python3 tools/compare/compare_instruction_masks.py --ida-csv /path/to/out.csv --binja-dir /tmp/lumina_debug
python3 tools/compare/compare_instruction_masks.py --ida-csv /path/to/out.csv --binja-dir /tmp/lumina_debug --ida-split-size 4
python3 tools/verify/verify_our_algorithm.py --dump-dir /tmp/lumina_dump
python3 tools/verify/verify_all_dumps.py
```

For AArch64 instruction-mask comparisons, `--ida-split-size 4` matters because IDA can emit CalcRel macro records spanning multiple 4-byte instructions.

### Archived research

`research/` preserves older brute-force experiments, mismatch investigations, one-off debugging probes, and historical test runners. Those files are useful for resumed reverse-engineering work, but they are not part of the normal build or supported user-facing workflow.

---

## Repository philosophy

Gamayun is intentionally opinionated in three ways:

1. **Parity over packet minimalism.** A Lumina client that produces the wrong hashes is worse than no client at all.
2. **Visibility over opacity.** Returned metadata should be inspectable, logged, and diffable, not silently applied from a black box.
3. **Conservative querying over noisy misses.** If Binary Ninja and IDA likely disagree about function layout, the safer move is to skip the query.

That is why the repository contains not only protocol code, but also a dedicated apply layer, a type decoder, a reliability filter, and validation tooling.

## Current scope and limitations

- **Read-side focus** - the implemented workflow is centered on `HELLO` + `PULL`, metadata decoding, and application inside Binary Ninja
- **Native UI plugin** - Binary Ninja must be restarted when reinstalling the plugin
- **Best-effort parity, not perfect identity** - the CalcRel engine is strong, but Binary Ninja / IDA function-layout disagreements can still exist, especially around split tails
- **Binary Ninja type acceptance still matters** - some decoded Lumina type declarations may be preserved as tags if Binary Ninja rejects the declaration text

## Summary

If `dazhbog` is the server-side answer to "how do we store and browse Lumina metadata outside IDA?", then **Gamayun** is the Binary Ninja-side answer to "how do we consume that metadata seriously inside Binary Ninja?"

It gives you a native UI, a parity-minded CalcRel engine, structured metadata decoding, safe application workflows, and the tooling needed to keep improving the match quality over time.
