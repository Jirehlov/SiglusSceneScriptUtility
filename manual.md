# SiglusSceneScriptUtility Manual

**Version:** See `siglus-ssu --version`

**Repository:** https://github.com/Jirehlov/SiglusSceneScriptUtility

**Chinese Manual:** [manual_cn.md](manual_cn.md)

---

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
   - [Option 1: Install from PyPI](#option-1-install-from-pypi)
   - [Option 2: Install from Source](#option-2-install-from-source)
3. [General Usage](#general-usage)
   - [Global Options](#global-options)
   - [Command Aliases](#command-aliases)
   - [Getting Help](#getting-help)
4. [Modes Reference](#modes-reference)
   - [init — Install / Refresh Required Constants](#init--install--refresh-required-constants)
   - [-lsp — Start the Language Server](#-lsp--start-the-language-server)
   - [-c / --compile — Compile Scripts](#-c----compile--compile-scripts)
   - [-x / --extract — Extract Files](#-x----extract--extract-files)
   - [-a / --analyze — Analyze and Compare Files](#-a----analyze--analyze-and-compare-files)
   - [-d / --db — Export and Compile `.dbs` Databases](#-d----db--export-and-compile-dbs-databases)
   - [-k / --koe — Collect Voice Files by Character](#-k----koe--collect-voice-files-by-character)
   - [-e / --exec / --execute — Execute at a Script Label](#-e----exec----execute--execute-at-a-script-label)
   - [-m / --textmap — Text Mapping for Translation](#-m----textmap--text-mapping-for-translation)
   - [-g / --g00 — Work with `.g00` Image Files](#-g----g00--work-with-g00-image-files)
   - [-s / --sound — Work with Audio Files](#-s----sound--work-with-audio-files)
   - [-v / --video — Work with `.omv` Video Files](#-v----video--work-with-omv-video-files)
   - [-p / --patch — Patch `SiglusEngine.exe`](#-p----patch--patch-siglusengineexe)
   - [-t / --tutorial — Build a Static Tutorial Graph](#-t----tutorial--build-a-static-tutorial-graph)
   - [test — Round-Trip Compile Test](#test--round-trip-compile-test)
5. [SiglusSceneScript Language Specification (SiglusSS; as Defined by `-c`)](#siglusss-language-spec)
6. [Tips and Troubleshooting](#tips-and-troubleshooting)

---

## Overview

**SiglusSceneScriptUtility** (abbreviated **SSSU** or invoked as **siglus-ssu**) is a command-line utility for working with files used by the **SiglusEngine** visual novel engine. It implements a SiglusSS compilation pipeline for the supported engine/resource set and provides a comprehensive set of tools for:

- Extracting and recompiling `.pck` scene files
- Analyzing binary formats (`.dat`, `.dbs`, `.gan`, `.sav`, `.cgm`, `.tcr`)
- Disassembling `.dat` compiled scripts
- Exporting and applying text maps for translation work
- Collecting and organizing character voice audio from `.ovk` files
- Extracting and recompiling `.g00` image files
- Decoding and re-encoding `.nwa` / `.owp` / `.ovk` audio files
- Extracting and recompiling `.omv` video files
- Patching `SiglusEngine.exe` for alternative key or language settings
- Providing an LSP for the SiglusSS language

> **Compatibility Notice:** Resource files from very old versions of **SiglusEngine** are not supported by this project. If a game uses an unusually old engine build, some related resource formats or constants may differ and the tools described in this manual may not work correctly.

---

## Installation

### Option 1: Install from PyPI

```bash
pip install siglus-ssu
```

After installation, if this machine does not already have a verified user-data `const.py`, run `init` once to install it:

```bash
siglus-ssu init
```

> **Note:** Python 3.12 or later is required. The package ships with a prebuilt native Rust extension for performance-critical operations. If no compatible wheel is available for your platform, you will need to build the Rust extension from source.
>
> `const.py` is stored in a platform-specific user data directory:
> - **Windows:** `%APPDATA%\siglus-ssu\const.py`
> - **Unix/Linux/macOS:** `~/.local/share/siglus-ssu/const.py` (or `$XDG_DATA_HOME/siglus-ssu/const.py`)

### Option 2: Install from Source

#### Prerequisites

- **Python 3.12+**
- **uv** — project manager ([installation guide](https://github.com/astral-sh/uv))
- **Rust toolchain** — required to build the native extension ([rustup.rs](https://rustup.rs/))

#### Steps

1. Clone the repository.
2. In the project root, run:

   ```bash
   uv sync
   ```

   This builds the Rust extension and installs all dependencies into a local virtual environment.

3. Prefix all commands with `uv run`:

   ```bash
   uv run siglus-ssu --help
   ```

   When running from this repository checkout, the bundled `src/siglus_ssu/const.py` is searched before the user-data copy. That means commands usually work immediately after `uv sync`. Run `uv run siglus-ssu init` only when you want to install or refresh the user-data copy, or when you are running from a layout that does not include the bundled source copy:

   ```bash
   uv run siglus-ssu init
   ```

---

## General Usage

```
siglus-ssu [-h] [-V|--version] [--legacy] [--legacy-full] [--const-profile N] (-lsp|init|-c|-x|-a|-d|-k|-e|-m|-g|-s|-v|-p|-t|test) [args]
```

### Global Options

| Option | Description |
|---|---|
| `-h`, `--help` | Show the help message and exit. |
| `-V`, `--version` | Show the program version and exit. |
| `--legacy` | Force the Python compile backend while keeping native helpers such as LZSS enabled. Useful for comparing compile behavior. |
| `--legacy-full` | Disable all Rust native acceleration and use the pure Python fallback implementation where available. Useful for debugging native extension issues. |
| `--const-profile N` | Select one of the built-in `const.py` profiles (`0`-`2`, default: `0`). Use a non-default profile only when targeting an engine/compiler variant whose form or element tables differ from the default profile. Cannot be combined with `-c --tmp`. |

### Command Aliases

The CLI also accepts a few convenience aliases:

- `siglus-ssu help` behaves the same as `siglus-ssu --help`
- `siglus-ssu version` behaves the same as `siglus-ssu --version`
- `siglus-ssu --init ...` behaves the same as `siglus-ssu init ...`

### Python Module API

This project supports the `siglus-ssu` command-line interface only. Importing or calling `siglus_ssu` modules from external Python code is not a supported API, and internal module names, functions, globals, and return shapes may change without compatibility guarantees.

### Getting Help

```bash
# Show the global help message, listing all modes
siglus-ssu --help

# Mode-specific --help currently falls back to the same global help page
siglus-ssu -lsp --help

# Other modes behave the same way
siglus-ssu -c --help
```

---

## Modes Reference

### `init` — Install / Refresh Required Constants

Installs the user-data `const.py` file containing engine-specific constants (opcode tables, key derivation parameters, etc.). When the file is missing or you force a refresh, `init` downloads it from the project's GitHub repository.

At normal startup, the loader searches a source-tree copy at `src/siglus_ssu/const.py` before the user-data copy. In this repository checkout, that bundled file is present, so source-tree runs may use it even after `init` installs a user-data copy.

Before using any mode other than `init`, make sure at least one verified `const.py` will be found. PyPI installs rely on the user-data copy because wheels exclude the bundled source-tree `const.py`; source-checkout runs from this repository can also use the bundled `src/siglus_ssu/const.py`.

#### Syntax

```
siglus-ssu init [--force | -f] [--ref <git-ref>]
```

#### Parameters

| Parameter | Description |
|---|---|
| `--force`, `-f` | Overwrite the user-data `const.py` even if one already exists. |
| `--ref <git-ref>` | Choose the Git branch, tag, or commit hash used when `init` downloads `const.py`. If the user-data target already exists, pair `--ref` with `--force` to actually redownload it. By default, `init` tries refs associated with the current package version, including matching version commits discovered from git/GitHub and tag-like refs. |

`init` only needs GitHub API access when it actually has to fetch `const.py`. If `--force` is not specified and the user-data target already exists, the command reuses that file instead of downloading it again, then verifies it while loading.

Any downloaded `const.py` is verified against a built-in SHA-512 allowlist. The built-in default ref mapping tracks the current supported package version; explicit `--ref` values still work as long as they resolve to an allowlisted `const.py` content.

#### Examples

```bash
# Ensure the default user-data const.py is installed
siglus-ssu init

# Redownload into the user-data location even if const.py already exists
siglus-ssu init --force

# Force a download from a specific tagged release
siglus-ssu init --force --ref v0.4.0
```

---

### `-lsp` — Start the Language Server

Starts a standard **stdio JSON-RPC / Language Server Protocol** service for the **SiglusSceneScript language** (abbreviated **SiglusSS language**) and for `.inc` declaration files.

#### Syntax

```
siglus-ssu -lsp [--serial]
```

#### Parameters

- `--serial`: Disable default parallel LSP workspace scanning and force serial scanning.

#### Notes

- Workspace-wide symbol and link scans run in parallel by default, using half of the available CPU count as the default worker count. A changed `.inc` rebuilds the directory index; changed `.ss` files reuse the current `.inc` context and are rescanned individually.
- When the Rust native scanner is available, LSP workspace scans and document symbols use it automatically and fall back to the Python pipeline if native scanning is unavailable or cannot handle the document.
- Workspace indexes persist across sessions. Cache compatibility includes the directory, `.inc` MD5 table, `.ss` file set, package version, and active `const.py` content/profile. A cached `.ss` entry is reused only when that file's MD5 still matches; unsaved editor overlays bypass the persistent index. The default cache directory is `%LOCALAPPDATA%\siglus_ssu\lsp-index` on Windows, `$XDG_CACHE_HOME/siglus_ssu/lsp-index` on Unix-like systems, or `~/.cache/siglus_ssu/lsp-index`; set `SIGLUS_SSU_LSP_CACHE_DIR` to override it.
- Capabilities include semantic tokens, publish/pull diagnostics, completion, hover, go to definition, references, rename and conditional prepare-rename support, document symbols, and live same-directory `.inc` overlay refresh for `.ss` analysis. Pull diagnostics are advertised only when the client supports `textDocument/diagnostic`. Semantic token categories include dialogue text, system elements, speaker names, and used/unused macro declarations.
- The server negotiates position encodings, returns range-aware completion edits, respects supported completion item kinds, supports work-done progress cancellation on long scans, and validates document URIs and request shapes.
- Analysis reuses the applicable `-c` pipeline stages (`CA`, `LA`, `SA`, `MA`, `BS`). Its project model is directory-based, matching `.inc` / `.ss` joint analysis and global `.inc #command` linking.

---

### `-c` / `--compile` — Compile Scripts

Compiles a directory of `.ss` SceneScript source files into a `.pck` file. During compilation, individual scene `.dat` files are first generated in a temporary directory, then in the normal mode they are linked and packed into the final `Scene.pck`. The compilation pipeline implements the supported SiglusEngine-style build stages, including LZSS compression, per-script string-table shuffling, and encryption based on `暗号.dat`.

By default, compile mode uses the Rust native backend when it is available and supported for the selected options, and falls back to the Python backend otherwise. Global `--legacy` forces the Python compile backend while still allowing native helpers such as LZSS; `--legacy-full` disables all Rust native acceleration.

When `--tmp` is not supplied, every compile invocation creates a uniquely named automatic temporary directory. Concurrent compiles targeting the same output directory therefore do not share intermediate files.

Scene names written into the linked `.pck` use the same ASCII-only lowercase normalization as the official compiler: `A` through `Z` become `a` through `z`, while non-ASCII characters, including fullwidth Latin letters such as `ＥＤ`, are preserved.

It also supports compiling `Gameexe.ini` → `Gameexe.dat` independently via `--gei`.

#### Syntax

```
# Standard compilation
siglus-ssu -c [options] <input_dir> <output_pck | output_dir>

# Compile only Gameexe.dat from an existing Gameexe.ini
siglus-ssu -c --gei <input_dir | Gameexe.ini> <output_dir>

# Compile with shuffle seed brute-force
siglus-ssu -c --test-shuffle [seed0] [--csv <seed_csv>] <input_dir> <output_pck | output_dir> <test_dir>
```

#### Parameters

| Parameter | Description |
|---|---|
| `<input_dir>` | Directory containing `.ss` source files, optionally alongside `.inc`, `.ini` / `Gameexe.ini`, and `暗号.dat`. |
| `<output_pck \| output_dir>` | Output path. If the argument names an existing directory, `Scene.pck` is created inside it. Otherwise the argument is treated as the output file path; a non-existent path that does not end in `.pck` is still written as that exact file name. |
| `--debug` | Keep intermediate temporary files (`.dat`, `.lzss`, etc.) after compilation. Cannot be combined with `--tmp`. |
| `--charset ENC` | Force source file encoding. Accepted values: `jis`, `cp932`, `sjis`, `shift_jis` (all equivalent to CP932/Shift-JIS), or `utf8`, `utf-8`. If omitted, the encoding is auto-detected. |
| `--no-os` | Skip the OS (Original Source) embedding stage. The `Scene.pck` is still generated and written out normally, but no original source files are embedded inside it. Does not affect encryption or compression of the scripts themselves. |
| `--dat-repack` | Instead of compiling `.ss` scripts, scan the immediate files in `input_dir` for existing Siglus scene `.dat` files, copy them, and pack them directly into a `.pck` file. Useful for packing already-compiled scripts. It can only be combined with `--no-os` and/or `--no-lzss`. Cannot be combined with `--tmp` or `--test-shuffle`. |
| `--no-angou` | Disable LZSS compression and XOR encryption, set `scn_data_exe_angou_mod = 0`, and omit original source embedding. Cannot be combined with `--tmp`. |
| `--no-lzss` | Disable the LZSS stage while keeping the usual script encryption/header behavior. Original source chunks are not embedded in this mode. This matches the official "easy link" style output. Cannot be combined with `--tmp`. |
| `--serial` | Disable multi-process parallel compilation and force the compile stage to run serially. Parallel compilation is enabled by default. |
| `--max-workers N` | Maximum number of parallel worker processes. Only effective while parallel compilation is enabled; defaults to auto. |
| `--set-shuffle SEED` | Set the initial MSVC-compatible `rand()` seed for the per-script string table shuffle. Accepts decimal or `0x...` hex. Default: `1`. Implies `--serial`. Cannot be combined with `--tmp`. |
| `--tmp <tmp_dir>` | Use a specific persistent temporary directory. When provided, an MD5 cache (`_md5.json`) is maintained inside this directory to enable **incremental compilation** — only changed `.ss` files are recompiled on subsequent runs. Cannot be combined with `--debug`, `--dat-repack`, `--no-angou`, `--no-lzss`, `--set-shuffle`, `--test-shuffle`, `--csv`, `--gei`, or global `--const-profile`. |
| `--test-shuffle [seed0]` | Scan 32-bit MSVC `rand()` seeds from `seed0` (default `0`) through `0xFFFFFFFF` to find one that reproduces the first scene's string-table order in `<test_dir>`, then verify that seed against every scene. Cannot be combined with `--tmp`. |
| `--csv <seed_csv>` | With `--test-shuffle`, write a CSV containing each scene object's initial seed and final seed from the serial rebuild pass. If the path is an existing directory or ends with a path separator, `test_shuffle_seeds.csv` is written inside it. Cannot be combined with `--tmp`. |
| `--gei` | Only run the `Gameexe.ini` → `Gameexe.dat` compilation stage. The output argument is always treated as a directory. If it does not exist, it is created, and `Gameexe.dat` is written inside it. Cannot be combined with `--tmp`. |

#### Compiling Stats

The compiler prints an `=== Compiling Stats ===` summary before exit for compile runs.

That summary includes:

- Per-stage elapsed time totals for the stages that ran (`GEI`, `IA`, `CA`, `LA`, `SA`, `MA`, `BS`, or `Compiling`)
- `inc_files`: number of `.inc` files participating in the build
- `scene_files`: total number of `.ss` files in the input directory
- `compiled_scene_files`: number of `.ss` files actually compiled in this run; under incremental compilation, this is the incremental subset only

When the run completes a normal full scene compilation, the summary additionally includes detailed project-wide statistics:

- `#replace`, `#define`, `#define_s`, and `#macro` totals together with their unused counts
- `read_flags` and `read_flags_scenes`
- source-side statistics for scene-local `#property` / `#command`, preprocessor directives, `#inc_start` blocks, labels, statements, expressions, operator kinds, string pools, and dialogue lines
- `binary_sizes`
- trailing `top5_*` detail lines: `top5_read_flags_scenes`, `top5_string_pool_scenes`, and `top5_dat_scenes`

Detailed project-wide statistics are omitted instead of printed as `n/a` when the run is not a normal full scene compilation, including `--tmp`, `--dat-repack`, `--test-shuffle`, `--gei`, missing `.ss` input, and partial or failed compile runs. The basic timing and file-count summary remains available when the corresponding stages ran.

#### Examples

```bash
# Compile a translation directory into a new Scene.pck
siglus-ssu -c /path/to/translation_work /path/to/Scene_translated.pck

# Compile with the default parallel workers and keep temp files for inspection
siglus-ssu -c --debug /path/to/src /path/to/out/

# Force serial compilation
siglus-ssu -c --serial /path/to/src /path/to/Scene.pck

# Incremental compilation: only recompile changed .ss files
siglus-ssu -c --tmp /path/to/cache /path/to/src /path/to/Scene.pck

# Compile with a specific shuffle seed (to match original output byte-for-byte)
siglus-ssu -c --set-shuffle 12345 /path/to/src /path/to/Scene.pck

# Brute-force the shuffle seed starting from 12345
siglus-ssu -c --test-shuffle 12345 /path/to/src /path/to/out/ /path/to/original_dats/

# Brute-force the shuffle seed and write per-scene initial/final seeds
siglus-ssu -c --test-shuffle 12345 --csv /path/to/seeds.csv /path/to/src /path/to/out/ /path/to/original_dats/

# Repack existing .dat files without re-compiling .ss files
siglus-ssu -c --dat-repack /path/to/dat_dir /path/to/Scene_repacked.pck

# Repack existing .dat files without LZSS
siglus-ssu -c --dat-repack --no-lzss /path/to/dat_dir /path/to/Scene_repacked.pck

# Only generate Gameexe.dat from an existing Gameexe.ini
siglus-ssu -c --gei /path/to/src /path/to/out/

# Force UTF-8 source encoding and disable encryption
siglus-ssu -c --charset utf8 --no-angou /path/to/src /path/to/out/
```

#### Notes

- **Auto-encoding detection:** If `--charset` is not specified, the utility scans `.ss`, `.inc`, `.ini`, and `.dat` files for a UTF-8 BOM or kana/CJK characters. If found, `utf-8` is used; otherwise, `cp932` (Shift-JIS) is assumed.
- **Incremental compilation:** When `--tmp` is specified, the compiler caches MD5 hashes of all `.ss` and `.inc` files. On the next run, only files whose hash has changed (or whose `.dat` is missing) are recompiled, and existing `.lzss` outputs are reused. If a scene source changes or its `.lzss` is missing, that scene's `.lzss` is regenerated. If any `.inc` file changes, a full recompile is triggered.
- **Shuffle seed:** The compiler shuffles each `.dat` string table with an MSVC-compatible `rand()` seed. String order does not affect normal translation work. `--test-shuffle` finds a seed from the first scene, rebuilds every scene serially, and reports any later mismatch while continuing to generate output; use `--set-shuffle` to rebuild with a known seed.

---

### `-x` / `--extract` — Extract Files

Extracts a `.pck` scene file into a timestamped directory containing decoded scene `.dat` files and any embedded original source files, or restores the `Gameexe.ini` plaintext from a binary `Gameexe.dat`.

#### Syntax

```bash
# Extract a .pck file
siglus-ssu -x [--disam|--decompile] <input_pck> [output_dir] [--angou <path|angou=text|key=bytes>]

# Batch-disassemble `.dat` files from a directory
siglus-ssu -x --disam <input_dir> [output_dir] [--angou <path|angou=text|key=bytes>]

# Restore Gameexe.ini from Gameexe.dat
siglus-ssu -x --gei <Gameexe.dat | input_dir> [output_dir] [--angou <path|angou=text|key=bytes>]
```

#### Parameters

| Parameter | Description |
|---|---|
| `<input_pck>` | Path to the `.pck` file to extract. |
| `<input_dir>` | Path to a directory scanned for `.dat` files when `--disam` is enabled. Only the immediate `.dat` files in that directory are processed. |
| `<output_dir>` | Directory where extracted files will be written. Optional for all `-x` modes. If omitted, output defaults to the input file directory, or to the input directory itself when the input is a directory. |
| `--disam` | With `.pck` input, also write `<scene>.dat.txt` disassembly. With directory input, scan only that directory's immediate `.dat` files and write `.dat.txt` into `<output_dir>`. Cannot be combined with `--gei`. Non-scene `.dat` files are skipped. |
| `--decompile` | With a complete `.pck` input, run the same disassembly pass as `--disam`, and additionally emit reconstructed `decompiled/<scene>.ss` files plus `decompiled/__decompiled.inc`. Single `.dat` files and `.dat` directories are not accepted. Cannot be combined with `--gei`. |
| `--angou <path\|angou=text\|key=bytes>` | Override or supplement the scene/Gameexe decryption key source. Uses the common key-source rules described in [`-a` / `--analyze`](#-a----analyze--analyze-and-compare-files). |
| `--gei` | Instead of extracting a `.pck`, decode a `Gameexe.dat` binary back to a `Gameexe.ini` plaintext file. The input can be the `.dat` file itself or its parent directory. Key candidates are tried using the common key-source rules. |

With `.pck` input, extracted files are written into `output_YYYYMMDD_HHMMSS/`. When embedded original sources are present, they are restored there alongside the decoded scene `.dat` files. A `--disam` run prints total disassembly timing; a `--decompile` run also prints decompile-hints and decompile timing summaries.

The current decompiler is experimental. Treat `--decompile` output in `decompiled/*.ss` as inspection output, not as a reliable reconstruction of the original source or a guaranteed round-trip input for release work.

#### Examples

```bash
# Extract Scene.pck into the translation_work directory
siglus-ssu -x /path/to/Scene.pck /path/to/translation_work/

# Extract Scene.pck next to the input file
siglus-ssu -x /path/to/Scene.pck

# Extract with `.dat` disassembly
siglus-ssu -x --disam /path/to/Scene.pck /path/to/translation_work/

# Extract with `.dat` disassembly and decompiled `.ss`
siglus-ssu -x --decompile /path/to/Scene.pck /path/to/translation_work/

# Extract encrypted scenes using an explicit key source
siglus-ssu -x /path/to/Scene.pck /path/to/translation_work/ --angou /path/to/game_dir/

# Batch-disassemble the `.dat` files in one directory
siglus-ssu -x --disam /path/to/scene_dir/

# Restore Gameexe.ini from Gameexe.dat
siglus-ssu -x --gei /path/to/Gameexe.dat /path/to/output/
```

---

### `-a` / `--analyze` — Analyze and Compare Files

Analyzes the internal structure of a supported binary file and prints a detailed report to standard output. When two files of the same type are provided, a structural comparison is performed.

#### Supported File Types

`.pck`, `.dat`, `.gan`, `.sav`, `.cgm`, `.tcr`

#### Syntax

```
# Analyze a .pck file
siglus-ssu -a <input_file.pck> [--angou <path|angou=text|key=bytes>]

# Analyze a .dat file
siglus-ssu -a [--disam] <input_file.dat> [--angou <path|angou=text|key=bytes>]

# Analyze or update other supported files
siglus-ssu -a [--readall|--apply] <input_file.sav>
siglus-ssu -a <input_file.(gan|sav|cgm|tcr)>

# Count dialogue units in a .pck only and write per-file CSV
siglus-ssu -a --word <input_pck> [output_csv] [--angou <path|angou=text|key=bytes>]

# Compare two .pck files
siglus-ssu -a [--payload] <input_file_1.pck> <input_file_2.pck> [--angou <path|angou=text|key=bytes>]

# Compare two .dat files
siglus-ssu -a [--payload] [--disam] <input_file_1.dat> <input_file_2.dat> [--angou <path|angou=text|key=bytes>]

# Compare two files without an explicit key source
siglus-ssu -a [--payload] <input_file_1> <input_file_2>

# Analyze or derive the exe_el key from a key source
siglus-ssu -a --angou <path|angou=text|key=bytes>

# Analyze or compare Gameexe.dat
siglus-ssu -a --gei <Gameexe.dat> [Gameexe.dat_2] [--angou <path|angou=text|key=bytes>]
```

#### Parameters

| Parameter | Description |
|---|---|
| `<input_file>` | Path to the file to analyze. Supported extensions: `.pck`, `.dat`, `.gan`, `.sav`, `.cgm`, `.tcr`. When analyzing or comparing `.pck` files, embedded `SCENE_SCRIPT_ID` values are shown in the existing tables as an `ID` column for embedded `.ss` source chunks; `.pck` comparisons also treat source IDs as comparison data. |
| `[input_file_2]` | Optional second file for comparison. If both files are the same type, a structural comparison is performed; if types differ, each file is analyzed separately. |
| `--disam` | When analyzing a `.dat` file or comparing two `.dat` files, write human-readable disassembly to `<scene>.dat.txt` alongside each input `.dat`. Prints total disassembly timing before the command finishes. Use `-x --decompile <input_pck>` for reconstructed `.ss` output. |
| `--readall` | Only meaningful for `read.sav` and `global.sav`. For `read.sav`: set all read-flag bits to `1` (marking every scene as read). For `global.sav`: unlock engine-managed collection fields in-place, currently `cg_table`, `bgm_table`, and `chrkoe.look_flag` when present. A non-overwriting `.bak` backup is created before writing. Cannot be combined with `--apply`, compare mode, `--word`, `--angou`, or `--gei`; `--disam` and `--payload` do not change this single-file `.sav` operation. Unrelated generic global flag arrays and external achievement backends such as Steam are not modified. |
| `--apply` | For `global.sav` only: read the sibling `global.txt` with the same base name, apply editable `G[n]`, `Z[n]`, `cg_table[n]`, `bgm_table[n]`, and `chrkoe[n].look_flag` entries, create a non-overwriting `.bak` backup, and rewrite the `.sav` in-place. Other generated fields such as `M`, `global_namae`, and character display names are ignored. Cannot be combined with `--readall`, compare mode, `--disam`, `--payload`, `--word`, `--angou`, or `--gei`. |
| `--word` | For `.pck` only: skips normal structural analysis, counts dialogue units for each decoded scene `.dat` and each embedded `.ss` source file, prints the per-file counts, and writes them to CSV. If `[output_csv]` is omitted, the CSV is written as `<input_pck_stem>.word.csv` next to the input `.pck`; if `[output_csv]` is an existing directory or ends with a path separator, that default CSV filename is written inside it. Can be combined with `--angou`. |
| `--payload` | **(Compare mode only)** For `.pck` and `.dat` comparisons, additionally compare normalized decoded/decompressed `scn_bytes` semantics. This ignores string-pool `str_id` differences when the resolved text is the same. `.pck` results distinguish `same`, `text_only` for resolved text changes only, `real_diff` for non-text scene-bytecode differences, and `-` when payload comparison is unavailable; `.dat` results use `identical`, `text_only`, `real_diff`, or `unavailable`. When the Rust native payload scanner is available, it is used automatically and falls back to Python otherwise. It is more expensive than a plain structural comparison, but helps distinguish text-only translation changes from real scene-behavior changes. |
| `--angou <path\|angou=text\|key=bytes>` | Explicit key source for `.pck`/`.dat` analysis, `.pck` word count, `Gameexe.dat` analysis, or standalone key derivation. `--angou` must be the final option in the command, must use the separated form `--angou VALUE`, and its value cannot be empty. A bare value is always treated as a path to a file or directory. Use `angou=text` for a literal `暗号.dat` first line, and `key=bytes` for a literal 16-byte `exe_el` key such as `key=0xA9,0x86,...`. During decryption, candidates are tried in order: explicit `--angou`; embedded `暗号.dat` inside the input `.pck`; current directory; parent directory. Lower-priority candidates are used only after a higher-priority source produced a key and that key failed validation; a missing, malformed, or keyless explicit source is reported as an input error. If `--angou` is a bare path, parent-directory probing is disabled for that request, so fallback stops after the current directory. Directory probing is not recursive. Inside each probed directory, the order is `Scene.pck`, then `Scene*.pck`, then `暗号.dat`, then `key.txt`, then `SiglusEngine*.exe`. |
| `--gei` | Analyze or compare `Gameexe.dat` files instead of general binary files. This mode can use `--angou`, but rejects other analyze modifiers such as `--disam`, `--readall`, `--apply`, `--payload`, and `--word`. |

Key-source diagnostics are printed to stderr whenever a decryption candidate is tried: each line includes the source, kind, path or inner file when applicable, the concrete `exe_el` value, and whether that candidate was accepted or rejected before falling back.

#### Examples

```bash
# Analyze Scene.pck — prints header info, file count, encryption status
siglus-ssu -a /path/to/Scene.pck

# Count dialogue units for each scene `.dat` and embedded `.ss`, then write CSV
siglus-ssu -a --word /path/to/Scene.pck

# Count dialogue units and write the CSV to an explicit path
siglus-ssu -a --word /path/to/Scene.pck /path/to/scene_counts.csv

# Analyze a compiled .dat script — prints header fields and string pool
siglus-ssu -a /path/to/script.dat

# Analyze an encrypted .dat script using a directory key source
siglus-ssu -a /path/to/script.dat --angou /path/to/game_dir/

# Compare two versions of Scene.pck — reports file additions, removals, and changes
siglus-ssu -a /path/to/Scene_original.pck /path/to/Scene_translated.pck

# Compare two Scene.pck files by normalized decoded `scn_bytes` semantics
siglus-ssu -a --payload /path/to/Scene_original.pck /path/to/Scene_translated.pck

# Write .dat disassembly to disk for inspection
siglus-ssu -a --disam /path/to/script.dat

# Set all read flags in read.sav to 1
siglus-ssu -a --readall /path/to/savedata/read.sav

# Unlock engine-managed collection flags in global.sav
siglus-ssu -a --readall /path/to/savedata/global.sav

# Generate global.txt, edit it, then write supported values back to global.sav
siglus-ssu -a /path/to/savedata/global.sav
siglus-ssu -a --apply /path/to/savedata/global.sav

# Derive the exe_el key from 暗号.dat
siglus-ssu -a --angou /path/to/暗号.dat

# Derive the exe_el key directly from a literal angou string
siglus-ssu -a --angou "angou=literal_angou_string"

# Derive the exe_el key from the SiglusEngine executable directly
siglus-ssu -a --angou /path/to/SiglusEngine.exe

# Derive the exe_el key from a literal 16-byte key
siglus-ssu -a --angou "key=0xA9,0x86,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00"

# Derive the exe_el key from a game directory
siglus-ssu -a --angou /path/to/game_dir/
```

#### Output Format (`.pck` example)

```
==== Analyze ====
file: /path/to/Scene.pck
type: pck
size: 123456789 bytes (0x75BCD15)
mtime: 2024-01-01 12:00:00
sha1: a1b2c3d4...

header:
  header_size=...
  scn_data_exe_angou_mod=...
  original_source_header_size=...
counts:
  inc_prop=...  inc_cmd=...
  scn_name=...  scn_data_index=...  scn_data_cnt=...
read_flags: ...
read_flags_scenes: ...
top5_read_flags_scenes: scene_a(...), scene_b(...), ...
...
```

If an embedded or adjacent `暗号.dat` is available, `.pck` analysis also appends a trailing `=== 暗号.dat ===` block and prints its first line, matching the compile-mode summary style.

#### Word Count Output (`-a --word`)

`-a --word` prints one row per decoded scene `.dat` and one row per embedded `.ss` source file. The count rule is as follows:

- Han, Hiragana, fullwidth/standalone Katakana, and Bopomofo count as `1` per character; a halfwidth Katakana base followed by a halfwidth voiced/semi-voiced mark counts as one unit
- Hangul counts by contiguous word run
- Other letters and numbers count by contiguous word run
- Internal `'`, `’`, `-`, `_`, `‐`, `‑`, `﹣`, and `－` keep one word run together when the nearest non-mark characters on both sides are Hangul, non-CJK letters, or numbers
- Internal `.`, `,`, `/`, `:`, and their fullwidth variants keep a numeric run together when both sides are decimal digits
- Punctuation, whitespace, emoji, and other symbols count as `0`

The CSV uses:

- `type` — `dat` or `ss`
- `path` — per-file relative path inside the `.pck`
- `status` — `ok` or `failed`
- `dialogue_lines` — number of counted dialogue entries
- `dialogue_count` — total counted dialogue units

---

### `-d` / `--db` — Export and Compile `.dbs` Databases

Works with `.dbs` binary database files that store tabular engine data.

Provides three sub-operations selected by `--x`, `--a`, or `--c`.

#### Syntax

```
# Export one or more .dbs files to CSV
siglus-ssu -d --x <input_dir | input_file.dbs> <output_dir>

# Analyze a .dbs file (or compare two)
siglus-ssu -d --a <input_file.dbs> [input_file_2.dbs]

# Compile CSV(s) back to .dbs
siglus-ssu -d --c [--type N] [--set-shuffle SEED] <input_csv | input_dir> <output_dbs | output_dir>

# Brute-force the MSVC rand() skip to match a reference .dbs
siglus-ssu -d --c [--type N] [--set-shuffle SEED] --test-shuffle [skip0] <expected.dbs> <input_csv> <output_dbs | output_dir>
```

#### Parameters

| Parameter | Description |
|---|---|
| `--x` | **Extract** mode: export `.dbs` → `.csv`. |
| `--a` | **Analyze** mode: dump structural info. With two arguments, compare two `.dbs` files. |
| `--c` | **Compile** mode: create `.dbs` from `.csv`. |
| `--type N` | Override the `m_type` field of the generated `.dbs` (integer). Default: `1`. |
| `--set-shuffle SEED` | Set the initial MSVC `rand()` seed for random padding bytes appended before packing. Accepts decimal or `0x...` hex. Default: `1`. |
| `--test-shuffle [skip0]` | Search up to 16,777,216 MSVC `rand()` skip counts from `skip0` (default `0`) to match the padding pattern at the end of a reference `.dbs`. Single-file mode only. |

#### Examples

```bash
# Export all .dbs files in a directory to CSV
siglus-ssu -d --x /path/to/dbs_dir/ /path/to/csv_out/

# Export a single .dbs file
siglus-ssu -d --x /path/to/gamedb.dbs /path/to/csv_out/

# Analyze a .dbs file
siglus-ssu -d --a /path/to/gamedb.dbs

# Compare two .dbs files
siglus-ssu -d --a /path/to/gamedb_original.dbs /path/to/gamedb_translated.dbs

# Compile a single CSV back to .dbs
siglus-ssu -d --c /path/to/gamedb.dbs.csv /path/to/gamedb_translated.dbs

# Compile a directory of CSVs to .dbs files
siglus-ssu -d --c /path/to/csv_dir/ /path/to/dbs_out/

# Compile with a specific shuffle seed and type
siglus-ssu -d --c --type 2 --set-shuffle 12345 /path/to/gamedb.dbs.csv /path/to/out.dbs

# Brute-force the rand-skip to match a reference .dbs exactly
siglus-ssu -d --c --test-shuffle /path/to/original.dbs /path/to/input.csv /path/to/output.dbs
```

With directory input, both `-d --x` and `-d --c` **recursively** scan subdirectories and preserve the relative directory structure in the output.

When compiling `m_type=0`, every string must encode strictly as Shift-JIS; other types use strict UTF-16LE encoding. An unencodable cell reports its CSV path, record start line, column, and call number, and no invalid `.dbs` is written.

#### CSV Format

The exported CSV uses UTF-8 BOM encoding with CRLF line endings and is compatible with Microsoft Excel. The first two rows are the `#DATANO` and `#DATATYPE` header rows, followed by data rows.

- `#DATANO` row: the first column is fixed to `#DATANO`, and the remaining columns are the call numbers of each column header.
- `#DATATYPE` row: the first column is fixed to `#DATATYPE`, and the remaining columns are the data type markers of the corresponding columns; the main types you will see are `S` (string) and `V` (numeric / other 32-bit unit).
- Data rows: the first column of each row is that row's row call number, and the remaining columns correspond to the column order defined by the first two rows.

Special characters in string values are handled by normal CSV quoting rather than by a custom backslash escape layer:

| Character | CSV Handling |
|---|---|
| `\` | Literal backslash; not an escape prefix. |
| `"` | Escaped by CSV quoting as doubled quotes when needed. |
| newline / carriage return | Stored as actual line-break characters inside quoted CSV fields. |
| TAB | Stored as an actual tab character. |

---

### `-k` / `--koe` — Collect Voice Files by Character

Scans compiled scene data from a `.pck`, a single scene `.dat`, or a directory tree of scene `.dat` files, reads KOE-related calls from disassembly traces, matches them against `.ovk` voice archive entries, and extracts the corresponding `.ogg` audio files. In normal mode, files are grouped into per-character subdirectories.

In normal mode, the command also generates a `koe_master.csv` manifest listing all found KOE entries with their character name, dialogue text, and call-site location. If the same `koe_no` is referenced by multiple distinct character/text pairs, the CSV keeps separate rows and only merges call-sites for the same `koe_no`/character/text tuple. When scanning a `.pck` directly, call-sites are reported as `Scene.pck!scene.dat:line`. After processing, the tool also computes the total duration of **referenced** voice files only; entries written under `unreferenced/` are explicitly excluded from that total. If a particular `.ogg` duration cannot be read, CSV output still succeeds, but that item is counted under `Duration failed`.

#### Syntax

```
siglus-ssu -k [--stats-only] <scene_input> <voice_dir> <output_dir> [--angou <path|angou=text|key=bytes>]
siglus-ssu -k [--stats-only] --single KOE_NO <voice_dir> <output_dir>
```

#### Parameters

| Parameter | Description |
|---|---|
| `<scene_input>` | Path to `Scene.pck`, a single scene `.dat`, or a directory tree of scene `.dat` files. Required in normal mode; not used with `--single`. |
| `<voice_dir>` | Path to the flat top-level directory containing `.ovk` voice archive files (typically named `z0001.ovk`, `z0002.ovk`, etc.). Can also be a direct path to a single `.ovk` file. In directory mode, only `.ovk` files in that directory itself are scanned; the search is not recursive and character subdirectories are not inspected. |
| `<output_dir>` | Directory where extracted `.ogg` files will be written. In normal mode, `koe_master.csv` is also written there. With `--single`, the extracted file is written directly under `<output_dir>`. |
| `--angou <path\|angou=text\|key=bytes>` | Key source used when scanning encrypted `Scene.pck` or scene `.dat` input. Uses the common key-source rules described in [`-a` / `--analyze`](#-a----analyze--analyze-and-compare-files). Not valid with `--single`. |
| `--stats-only` | Prints the summary and does not write any `.ogg` files. In normal mode it still writes `koe_master.csv`; with `--single`, no CSV is written. |
| `--single KOE_NO` | Only extracts the specified global KOE number. In this mode, no scene input is required, no `koe_master.csv` is generated, no character-name or `unreferenced` subdirectories are created, and the output file is written directly as `<output_dir>/KOE(XXXXXXXXX).ogg`. |

#### Output Structure

```
<output_dir>/
  koe_master.csv           — Master manifest of all KOE entries
  <CharacterName or %EMPTY>/ — One subdirectory per character name; %EMPTY when no name is inferred
    KOE(000000001).ogg
    KOE(000000002).ogg
    ...
  unreferenced/            — Entries in .ovk not referenced by any scanned scene
    KOE(000000003).ogg
    ...
```

Character names used as directory segments are percent-escaped without changing the value stored in `koe_master.csv`. Path separators, control and Windows-invalid characters, literal `%`, trailing spaces or dots, reserved device names, and the tool's fixed output names are encoded distinctly instead of being collapsed to one replacement character. Names that differ only by case still follow the target file system's case-sensitivity rules.

With `--single`, the output structure becomes:

```
<output_dir>/
  KOE(123456789).ogg
```

#### Examples

```bash
# Collect all voice files directly from Scene.pck
siglus-ssu -k /path/to/Scene.pck /path/to/voice/ /path/to/voice_out/

# Collect from encrypted scene data using an explicit key source
siglus-ssu -k /path/to/Scene.pck /path/to/voice/ /path/to/voice_out/ --angou /path/to/game_dir/

# Collect from a decoded scene `.dat` directory
siglus-ssu -k /path/to/scene_dir/ /path/to/voice/ /path/to/voice_out/

# Collect from a single scene `.dat` file
siglus-ssu -k /path/to/chapter1.dat /path/to/voice/ /path/to/voice_out/

# Generate CSV and summary only, without writing any `.ogg`
siglus-ssu -k --stats-only /path/to/Scene.pck /path/to/voice/ /path/to/voice_out/

# Extract only one global KOE entry
siglus-ssu -k --single 123456789 /path/to/voice/ /path/to/voice_out/
```

#### `koe_master.csv` Format (Normal Mode Only)

| Column | Description |
|---|---|
| `koe_no` | The global KOE number (scene_no × 100000 + entry_no). Kept when known even if the OVK entry was not found. If a KOE is referenced by multiple distinct character/text pairs, the same number can appear on multiple rows. |
| `character` | Character name inferred from `CD_NAME` events and inline voice metadata in the scene trace. |
| `text` | Dialogue text inferred from `CD_TEXT` events and inline voice metadata in the scene trace. |
| `duration_sec` | Voice duration in seconds, derived from the OVK entry sample count and Ogg sample rate. Empty when the OVK entry or duration metadata cannot be read. |
| `callsite` | Semicolon-separated list of `filename:line` locations where this KOE/text row is called, or `Scene.pck!scene.dat:line` when scanning a `.pck` directly. |

#### Summary Output

After completion, a summary is printed to stderr:

```
=== koe_collector summary ===
Stats only       : yes
Single KOE       : 123456789
OVK entries      : 45,678
OVK files        : 56
OVK z-files      : 56
OVK table errors : 0
Scene files      : 128
Scene callsites  : 44,210
Scene missing    : 124
KOE total        : 45,678
KOE referenced   : 44,086
KOE unreferenced : 1,592
KOE multi-text   : 3
KOE multi-text no: 200259, 2300267, 30100310
Audio extracted  : 43,900
Audio skipped    : 186
Audio failed     : 0
Voice duration   : 123,456.789 sec (34:17:36.789) [referenced only]
Duration counted : 44,086
Duration failed  : 0
CSV path         : /path/to/voice_out/koe_master.csv
CSV rows         : 45,724
Out dir          : /path/to/voice_out/
```

The example above shows normal-mode output. `Stats only` and `Single KOE` are only shown when the corresponding option is used. `KOE multi-text` counts scanned `koe_no` values associated with more than one non-empty dialogue text, and `KOE multi-text no` lists those values. This list is computed from scene references before OVK matching, and missing OVK call-sites keep their known `koe_no` in the CSV. With `--single`, scene-scanning and CSV-related lines are omitted.

---

### `-e` / `--exec` / `--execute` — Execute at a Script Label

Launches the `SiglusEngine.exe` directly to a specific scene and `#z` label. This is useful for quickly jumping to a particular scene during testing without replaying the full game.

#### Syntax

```
siglus-ssu -e <path_to_engine> <scene_name> <label>
```

#### Parameters

| Parameter | Description |
|---|---|
| `<path_to_engine>` | Absolute or relative path to `SiglusEngine.exe`. Quotes are stripped automatically. |
| `<scene_name>` | The script name without directory (e.g., `opening` or `opening.ss`). Must be a bare filename without path components. |
| `<label>` | The `#z` label number to jump to. The `#z` prefix is optional — `10`, `z10`, and `#z10` are all accepted. |

#### How It Works

The utility creates a temporary `work_YYYYMMDD` directory next to the engine executable and launches it with the following command-line arguments:

```
SiglusEngine.exe /work_dir=<work_dir> /start=<scene_name> /z_no=<label> /end_start
```

The engine is launched as a detached subprocess; the utility returns immediately after launch.

#### Examples

```bash
# Jump to label #z5 in the scene named "chapter2"
siglus-ssu -e /path/to/SiglusEngine.exe chapter2 5

# The .ss extension is stripped automatically
siglus-ssu -e /path/to/SiglusEngine.exe chapter2.ss z5

# With explicit #z prefix
siglus-ssu -e /path/to/SiglusEngine.exe chapter2 "#z5"
```

---

### `-m` / `--textmap` — Text Mapping for Translation

Exports string tokens from `.ss` source files or compiled `.dat` files to a CSV "text map", and applies translated text back from the CSV to the source files. This provides an alternative translation workflow that avoids directly editing `.ss` files.

#### Syntax

```
# Export text map from .ss source(s)
siglus-ssu -m <path_to_ss | path_to_dir>

# Apply translated text map back to .ss source(s)
siglus-ssu -m --apply <path_to_ss | path_to_dir>

# Export string list from compiled .dat file(s)
siglus-ssu -m --disam <path_to_dat | path_to_dir> [--angou <path|angou=text|key=bytes>]

# Apply translated string list back to compiled .dat file(s)
siglus-ssu -m --disam-apply <path_to_dat | path_to_dir> [--angou <path|angou=text|key=bytes>]
```

#### Parameters

| Parameter | Description |
|---|---|
| `<path_to_ss \| path_to_dir>` | A single `.ss` file or a directory of `.ss` files. Exactly one path argument is required. Directory inputs are scanned recursively. |
| `<path_to_dat \| path_to_dir>` | A single `.dat` file or a directory. Exactly one path argument is required. |
| `--apply`, `-a` | Apply a `.ss.csv` text map back to the corresponding `.ss` file in-place. The `.ss.csv` must already exist alongside the `.ss` file. |
| `--disam` | Export the string list from a compiled `.dat` to a `.dat.csv` file alongside the `.dat`. Works on encrypted, LZSS-compressed, or raw `.dat` files. When given a directory, `.dat` files are recursively scanned, and `Gameexe.dat` and `暗号.dat` are automatically excluded. |
| `--disam-apply` | Apply a `.dat.csv` translated string list back to the compiled `.dat` in-place. `--apply`, `--disam`, and `--disam-apply` are mutually exclusive. |
| `--angou <path\|angou=text\|key=bytes>` | Key source for `--disam` / `--disam-apply` on encrypted compiled `.dat` files. Uses the common key-source rules described in [`-a` / `--analyze`](#-a----analyze--analyze-and-compare-files). When the input is a directory, key candidates are resolved once for that directory and reused for every `.dat` file in the scan. Not valid for `.ss` text-map export/apply. |

#### Workflow: `.ss` Files

1. **Export the text map:**

   ```bash
   # Single file
   siglus-ssu -m /path/to/scripts/chapter1.ss
   # → writes /path/to/scripts/chapter1.ss.csv

   # Entire directory
   siglus-ssu -m /path/to/scripts/
   # → writes one .ss.csv per .ss file
   ```

2. **Edit `chapter1.ss.csv`:** Fill in the `replacement` column with translated text.

   The exported `.ss.csv` also includes a `kind` column:
   `1 = dialogue`, `2 = speaker name`, `3 = other text`.

   `replacement` is always a string value, not raw `.ss` source text. CSV quoting is handled by the CSV reader before textmap processing; any double quotes that remain in the parsed cell are literal text and are escaped as `\"` when `.ss` source is written. There is no implicit raw-literal mode based on leading or trailing quotes.

3. **Apply the translated text map:**

   ```bash
   siglus-ssu -m --apply /path/to/scripts/chapter1.ss
   # or equivalently:
   siglus-ssu -m -a /path/to/scripts/chapter1.ss
   ```

   After applying, the tool automatically performs a **bracket content fix** on the modified file: it removes unquoted ASCII spaces inside `【】` name brackets and drops extra invalid double-quote characters after bracket content has started. Per-file fix detail is reported to stderr; the final summary is printed to stdout.

   Application resolves each CSV row against the current source entry and uses the span obtained from the current parse rather than a potentially stale CSV span. Duplicate rows targeting one entry or replacements whose current spans overlap abort that file before write-back.

#### Workflow: Compiled `.dat` Files

1. **Export string list:**

   ```bash
   siglus-ssu -m --disam /path/to/chapter1.dat
   # → writes /path/to/chapter1.dat.csv
   ```

2. **Edit `chapter1.dat.csv`:** Fill in the `replacement` column.

3. **Apply translations:**

   ```bash
   siglus-ssu -m --disam-apply /path/to/chapter1.dat
   ```

   The `.dat` file is rewritten in-place preserving its original encryption and LZSS state.

#### `.ss.csv` Format

| Column | Description |
|---|---|
| `index` | Unique sequential token index (1-based). |
| `line` | Line number in the source `.ss` file. |
| `order` | Occurrence order of this token on the given line (1-based). |
| `start` | Absolute character offset of the token's inner content. |
| `span_start` | Absolute offset of the full token span (including quotes if any). |
| `span_end` | Absolute offset of the end of the full token span. |
| `quoted` | `1` if the token was quoted with `"..."` in source, `0` otherwise. |
| `kind` | Token kind: `1 = dialogue`, `2 = speaker name`, `3 = other text`. |
| `original` | The original string value (escape-encoded). |
| `replacement` | Translated string value to apply back to the source file. Initially identical to `original`; never interpreted as raw `.ss` source. |

Special characters in `original` and `replacement` are escape-encoded:

| Escape | Meaning |
|---|---|
| `\\` | Literal backslash |
| `\n` | Newline |
| `\r` | Carriage return |
| `\t` | Tab |

For `.ss.csv`, these escapes describe the CSV text value. When applying to `.ss`, the tool serializes that value back into valid SiglusSS source and preserves literal double quotes, backslashes, newlines, and tabs. Replacement values containing carriage returns are skipped because SiglusSS source preprocessing removes physical carriage-return characters. `.dat.csv` replacement can still store carriage returns directly in the compiled string table.

#### `.dat.csv` Format

| Column | Description |
|---|---|
| `index` | String index (`str_id`) in the compiled string table. |
| `kind` | String kind: `1 = dialogue`, `2 = speaker name`, `3 = other text`. |
| `original` | The original string value (escape-encoded). |
| `replacement` | The replacement string value (escape-encoded). Initially identical to `original`. |

---

### `-g` / `--g00` — Work with `.g00` Image Files

Provides tools for analyzing, extracting, merging, creating, and updating `.g00` image archives used by SiglusEngine for backgrounds, sprites, and other visuals.

#### `.g00` File Types

| Type | Description |
|---|---|
| type0 | LZSS32-compressed BGRA (32-bit) image. |
| type1 | LZSS-compressed paletted image (up to 256 colors). |
| type2 | Multi-cut composite image (sprite sheet) containing multiple indexed cuts. |
| type3 | XOR-obfuscated JPEG image. |

> **Note:** `--a` never requires Pillow. Extracting type3 JPEG payloads can run without Pillow, but PNG decoding, merge mode, create mode (including type3 create, which reads JPEG dimensions), and type0/type1/type2/type3 update paths require [Pillow](https://pillow.readthedocs.io/) (`pip install pillow`).

#### Syntax

```
# Analyze a .g00 file (no Pillow required)
siglus-ssu -g --a <input_g00>

# Extract .g00 to PNG/JPEG files
siglus-ssu -g --x [--trim] <input_g00 | input_dir> <output_dir>

# Merge multiple .g00 files (or cuts) into a single PNG
siglus-ssu -g --m [--trim] <input_g00[:cutNNN]> <input_g00[:cutNNN]> [...] [--o <output_dir>]

# Create a new .g00 from image files, or update from an explicit reference .g00
siglus-ssu -g --c [--type N] [--refer <ref_g00 | ref_dir>] <input_png | input_jpeg | input_json | input_dir> [output_g00 | output_dir]
```

#### Parameters

| Parameter | Description |
|---|---|
| `--a` | **Analyze** mode. Prints type, canvas size, and LZSS stats; for type2, also prints detailed information for up to the first 50 cuts. |
| `--x` | **Extract** mode. Decodes each `.g00` and writes PNG or JPEG files; for type2, also writes a round-trippable `.type2.json` sidecar unless `--trim` is used. Existing image or JSON targets are skipped rather than overwritten. |
| `--trim` | With `--x`, crop extracted images before writing them. PNG outputs are cropped to non-transparent pixels, falling back to the top-left background color when fully opaque; JPEG outputs use the top-left background color and keep the original payload when no crop is needed. Type2 JSON sidecars are not written when trimming. With `--m`, crop transparent or opaque-background edges from the merged PNG. |
| `--m` | **Merge** mode. Composites multiple `.g00` images or cuts into one PNG. With `--trim`, crops transparent or opaque-background edges from the merged PNG. |
| `--c` | **Create/update** mode. Without `--refer`, creates a new `.g00`. With `--refer`, updates image payload using the referenced `.g00` as the base. |
| `--o <output_dir>`, `-o`, `--output`, `--output-dir` | (Merge mode only) Optional output directory for the merged PNG. If omitted, the file is written to the current working directory. |
| `--type N`, `--t N` | (Only valid with `--c`) In create mode, force the output `.g00` type. In update mode, override the expected reference `.g00` type for validation. |
| `--refer <ref_g00 \| ref_dir>` | (Only valid with `--c`) Use an existing `.g00` as the explicit base for update semantics. Single-file input accepts either a `.g00` file or a directory; directory input requires a reference directory. If the output path is omitted in update mode, single-file input defaults to writing back to the reference `.g00`, and directory input defaults to writing back to the reference directory. |
| `<g00spec>[:cutNNN]` | For merge mode, optionally select a specific cut index from a type2 `.g00` by appending `:cutNNN` (e.g., `bg_day.g00:cut002`). |

#### Examples

```bash
# Analyze a type2 sprite sheet
siglus-ssu -g --a /path/to/sprite.g00

# Extract all .g00 files in a directory to PNG/JPEG
siglus-ssu -g --x /path/to/g00_dir/ /path/to/png_out/

# Extract a single .g00
siglus-ssu -g --x /path/to/bg_clear.g00 /path/to/png_out/

# Merge two sprite layers into one composite PNG
siglus-ssu -g --m /path/to/char_base.g00 /path/to/char_eye.g00 --o /path/to/merged_out/

# Merge a specific cut from a type2 .g00
siglus-ssu -g --m /path/to/sprite.g00:cut005 /path/to/overlay.g00 --o /path/to/out/

# Merge and crop the output PNG edges
siglus-ssu -g --m --trim /path/to/char_base.g00 /path/to/char_eye.g00 --o /path/to/merged_out/

# Create a new type0 .g00 from a PNG (output optional)
siglus-ssu -g --c /path/to/new_bg.png /path/to/game_bg.g00

# Omit output path: create <input_basename>.g00 next to the input image
siglus-ssu -g --c /path/to/new_bg.png

# Create a new type3 .g00 from a JPEG
siglus-ssu -g --c /path/to/op.jpeg /path/to/op.g00

# Create or rebuild a type2 .g00 directly from a .type2.json layout
siglus-ssu -g --c --type 2 /path/to/char_face.type2.json /path/to/char_face.g00

# Batch create type2 .g00 files from a directory of .type2.json layouts
siglus-ssu -g --c --type 2 /path/to/layout_dir/ /path/to/out_g00/

# Update an existing .g00 using an explicit reference
siglus-ssu -g --c /path/to/new_bg.png /path/to/game_bg.g00 --refer /path/to/original_bg.g00

# Batch update using a reference directory
siglus-ssu -g --c /path/to/updated_pngs/ /path/to/out_g00/ --refer /path/to/original_g00/
```

Directory input for `-g --x` scans only the immediate directory level for `.g00` files.
With `--trim`, type2 `.type2.json` sidecars are not written because the cropped images are no longer a rebuild layout.

#### Create Mode Notes

- Create mode is selected when `--refer` is omitted.
- Implemented create targets are **type0**, **type2**, and **type3**.
- Default inference is: `png` -> type0, `jpg/jpeg` -> type3. Use `--type 2` and pass a `.type2.json` directly for type2 creation.
- For type2 rebuilds produced by `-g --x`, pass the generated `.type2.json` directly to `-g --c`. Do not pass a single `*_cutNNN.png` file to create a multi-cut type2 archive.
- `--c` directory input currently scans only the **immediate level** of files, not recursively.
- `.type2.json` can only be used for creating/rebuilding type2; it cannot be used with `--refer` for update mode.
- In update mode, if the output path is omitted: single-file input defaults to writing back to the reference `.g00`; directory input defaults to writing back to the reference directory. Back up original assets before operating on them.
- `type1` create is still not implemented.

#### Type2 JSON Layout

`type2` create is driven by a JSON layout, not by CutText or PSD metadata. The recommended strict schema is:

```json
{
  "type": 2,
  "canvas": { "width": 2048, "height": 2048 },
  "default_center": { "x": 1023, "y": 0 },
  "cuts": [
    {
      "index": 0,
      "source": "face/base.png",
      "canvas_rect": { "x": 0, "y": 0, "w": 2048, "h": 2048 }
    },
    {
      "index": 1,
      "source": "face/blink.png",
      "canvas_rect": { "x": 0, "y": 0, "w": 2048, "h": 2048 }
    }
  ]
}
```

Notes:
- Root fields used by the strict schema are: `type`, `canvas`, optional `default_center`, and `cuts`.
- `canvas` is the output type2 canvas size.
- `cuts[]` is ordered by index. You may insert `null` to leave holes.
- Each non-null cut should provide `source` and `canvas_rect`.
- `source` is resolved relative to the JSON file.
- `canvas_rect` is the cut rectangle written into the outer type2 cut table.
- `source_rect` is optional. If omitted, the full source image is used; if `canvas_rect` is also present, its width and height must match that full source image. When both `source_rect` and `canvas_rect` are present, they must have the same width and height.
- `center` is optional per cut and defaults to `default_center` or `(0,0)`.
- Recommended practice for strict, reproducible rebuilds: keep one JSON file beside the extracted PNG set and edit only the PNG pixels or the explicit rect/center fields you actually intend to change.

#### Type2 Extract / Rebuild Asset Convention

When `-g --x` extracts a type2 `.g00` without `--trim`, it writes a JSON sidecar next to the images unless that target already exists:
- Single-cut: `<basename>.png` + `<basename>.type2.json`
- Multi-cut: `<basename>_cut000.png`, `<basename>_cut001.png`, ... + `<basename>.type2.json`

Notes:
- Extracted type2 PNGs preserve RGB under fully transparent pixels (hidden RGB). This is the default extraction behavior for type2.
- The generated `<basename>.type2.json` is the canonical rebuild layout for the extracted assets.
- Rebuild mode respects the input PNG exactly as-is. No hidden-RGB recovery or synthesis step is applied during type2 creation.

Direct rebuild from extracted assets:

```bash
# Step 1: extract a multi-cut type2 archive
siglus-ssu -g --x /path/to/char_face.g00 /path/to/work/

# Produces:
#   /path/to/work/char_face.type2.json
#   /path/to/work/char_face_cut000.png
#   /path/to/work/char_face_cut001.png
#   ...

# Step 2: edit one or more extracted PNG files in place

# Step 3: rebuild by passing the .type2.json file directly to -g --c
siglus-ssu -g --c --type 2 /path/to/work/char_face.type2.json /path/to/rebuilt/char_face.g00
```

For multi-cut type2 archives, the `.type2.json` file is the create input. The referenced PNG files are resolved from the JSON file location.

To update a specific cut, place an image named `<basename>_cut###.png` in the input directory when running `--c --refer ...`.

---

### `-s` / `--sound` — Work with Audio Files

Provides tools for decoding, extracting, analyzing, and re-encoding audio files used by SiglusEngine.

#### Supported Formats

| Extension | Description |
|---|---|
| `.nwa` | NWA Adaptive differential PCM compressed audio. Decodes to `.wav`. |
| `.owp` | XOR-obfuscated Ogg Vorbis audio. Decodes to `.ogg`. |
| `.ovk` | Ogg Vorbis archive containing multiple numbered voice entries. Extracts to individual `.ogg` files. |

#### Syntax

```
# Extract / decode audio files
siglus-ssu -s --x <input_dir | input_file> <output_dir> [--trim <path_to_Gameexe.dat | Gameexe.ini>] [--angou <path|angou=text|key=bytes>]

# Analyze an audio file, or compare two .ovk archives
siglus-ssu -s --a <input_file.(nwa | ovk | owp)> [input_file_2.ovk]

# Create / re-encode audio files
siglus-ssu -s --c <input_ogg | input_dir> <output_dir>

# Play one looped BGM or directory playlist using Gameexe loop points
siglus-ssu -s --play <input_file.(nwa | owp | ogg) | input_dir> [path_to_Gameexe.dat | Gameexe.ini] [--angou <path|angou=text|key=bytes>]
```

#### Parameters

| Parameter | Description |
|---|---|
| `--x` | **Extract** mode. Decodes `.owp` → `.ogg`, `.nwa` → `.wav`, `.ovk` → individual `.ogg` files. |
| `--a` | **Analyze** mode. Prints detailed structural header information for one audio file. When two `.ovk` files are provided, compares entries by entry number/occurrence using size, sample count, and decoded Ogg payload content; for `z####.ovk` filenames it also reports the derived global KOE label. |
| `--c` | **Create** mode. Encodes `.ogg` files → `.owp`, or groups of numbered `.ogg` files → `.ovk` archives. Directory input recursively scans for `.ogg` files and preserves the relative directory structure in the output. |
| `--play` | **Play** mode. Plays one `.nwa` / `.owp` / `.ogg` BGM or an interactive directory playlist using the `#BGM.*` loop-point table from `Gameexe.dat` or `Gameexe.ini`. The Gameexe path is optional; if omitted, the tool auto-detects a nearby `Gameexe.dat`/`Gameexe.ini`. Playback runs in a full-screen terminal UI with a live progress bar and playlist view. Requires `ffplay` to be on the system `PATH` and [psutil](https://pypi.org/project/psutil/) to be installed. |
| `--trim <Gameexe.dat \| Gameexe.ini>` | (Extract mode only) Read the `#BGM.*` loop-point table from `Gameexe.dat` or `Gameexe.ini` and trim `.owp` and `.nwa` BGM files to their loop regions. `.owp` trimming uses **ffmpeg** and writes `.ogg`; `.nwa` trimming slices decoded PCM directly and writes `.wav`. `.ovk` files are not trimmed. |
| `--angou <path\|angou=text\|key=bytes>` | Key source for encrypted `Gameexe.dat` when a Gameexe source is read, such as `--x --trim` or `--play`. Uses the common key-source rules described in [`-a` / `--analyze`](#-a----analyze--analyze-and-compare-files). Accepted but ignored by sound operations that do not read a Gameexe source. |

#### Examples

```bash
# Decode all audio in a directory
siglus-ssu -s --x /path/to/bgm/ /path/to/ogg_out/

# Decode a single .ovk voice archive
siglus-ssu -s --x /path/to/z0001.ovk /path/to/ogg_out/

# Decode .owp BGM files and trim to loop region using Gameexe.dat
siglus-ssu -s --x /path/to/bgm/ /path/to/ogg_out/ --trim /path/to/Gameexe.dat

# Decode and trim with an explicit Gameexe.dat key source
siglus-ssu -s --x /path/to/bgm/ /path/to/ogg_out/ --trim /path/to/Gameexe.dat --angou /path/to/game_dir/

# Decode .nwa BGM files and trim to loop region using Gameexe.dat
siglus-ssu -s --x /path/to/nwa_bgm/ /path/to/wav_out/ --trim /path/to/Gameexe.dat

# Analyze an .nwa file header
siglus-ssu -s --a /path/to/bgm01.nwa

# Analyze an .ovk archive table
siglus-ssu -s --a /path/to/z0001.ovk

# Compare two .ovk archives
siglus-ssu -s --a /path/to/old/koe/z0001.ovk /path/to/new/koe/z0001.ovk

# Analyze an .owp file
siglus-ssu -s --a /path/to/bgm01.owp

# Play one .owp BGM from its start point and loop forever using Gameexe.dat
siglus-ssu -s --play /path/to/bgm01.owp /path/to/Gameexe.dat

# Play one .ogg BGM using Gameexe.ini directly
siglus-ssu -s --play /path/to/bgm01.ogg /path/to/Gameexe.ini

# Play all matching BGM files in a directory; auto-detect Gameexe.dat/Gameexe.ini
siglus-ssu -s --play /path/to/BGM/

# Re-encode .ogg files back to .owp
siglus-ssu -s --c /path/to/translated_ogg/ /path/to/owp_out/
```

#### OVK Extraction Naming

When extracting a `.ovk` with multiple entries, output files are named:
- `<basename>.ogg` — if only one entry.
- `<basename>_<entry_no>.ogg` — if multiple entries (e.g., `z0001_0.ogg`, `z0001_1.ogg`).

#### OVK Creation Naming

When creating `.ovk` from a directory, files named `<basename>_<N>.ogg` (where `N` is an integer) are only grouped into a single `<basename>.ovk` when at least two files share the same basename. If a group contains only one numerically-suffixed file, the current implementation treats it as a regular single-file input and produces an `.owp`. Files without a numeric suffix are also individually encoded as `.owp`.

#### Sound Trim Details

The `--trim` option reads the Gameexe.dat/Gameexe.ini BGM table (entries formatted as `#BGM.N = "...", "filename", start, end, repeat`) and trims matching `.owp` and `.nwa` files to the samples between `repeat` and `end`. For `.owp`, it decodes to `.ogg` and calls **ffmpeg** to write the trimmed `.ogg`. For `.nwa`, it decodes to PCM, slices the sample range directly, and writes a trimmed `.wav` without requiring ffmpeg. `.ovk` files are not trimmed. This is useful for extracting seamlessly-loopable background music.

#### Loop Playback Details

The `--play` option reads the Gameexe BGM table from either `Gameexe.dat` or `Gameexe.ini` and matches entries by input basename. The Gameexe path is optional; when omitted, the tool looks in the parent directory of the audio folder for `Gameexe.dat`, then falls back to the first nearby `Gameexe.*` file (preferring `Gameexe.ini`).

If multiple `#BGM.*` rows point at the same physical file, the player keeps every candidate instead of letting the last row overwrite the others. It first prefers the row whose `#BGM` name matches the current basename exactly, then falls back to the first row for that file.

It accepts `.nwa`, `.owp`, and plain `.ogg` input. `.nwa` files are decoded to temporary `.wav` data before playback. Playback builds an **ffplay** filter from the Gameexe sample points: when `start < repeat`, it plays `start` → `repeat` once and then loops `repeat` → `end`; when `start == repeat`, it loops `repeat` → `end`; when `start > repeat`, it plays `start` → `end` once and then loops back to `repeat` → `end`. If `end = -1` or `end` extends past the decoded audio length, playback treats EOF as the loop end.

When the input is a directory, the player recursively scans `.nwa`/`.owp`/`.ogg` files, builds a playlist from files with matching `#BGM.*` entries, skips unmatched files with a diagnostic, and opens a full-screen terminal UI. The header shows the current file's full path, the status line reports whether playback is in the first pass, loop section, or paused state, and the bottom line still accepts typed commands.

The player accepts `p` (pause/resume), `q` (stop), `h` (help), and in playlist mode also `b` (previous), `n` (next), `l` (recenter the playlist around the current track), `play N` (jump to a 1-based track index), `u` / `d` (scroll by one page), and `gg` / `G` (jump to the top or bottom). This mode is intended for BGM loop preview and does not support `.ovk`.

Directory input for `-s --x` also recursively scans subdirectories and preserves the relative directory structure in the output.

---

### `-v` / `--video` — Work with `.omv` Video Files

Provides tools for analyzing, extracting, and recompiling `.omv` video files. The `.omv` format is an Ogg container (`.ogv`) with a proprietary SiglusEngine wrapper header.

`-v --c` keeps only the first Theora video stream from the input Ogg file. If the input also contains Vorbis, Opus, subtitles, or other streams, those streams are ignored and are not preserved in the generated `.omv`.

#### Syntax

```
# Extract .omv to .ogv (raw Ogg video)
siglus-ssu -v --x <input_dir | input_file.omv> <output_dir>

# Analyze an .omv file (structural info)
siglus-ssu -v --a <input_file.omv>

# Wrap an .ogv into an .omv
siglus-ssu -v --c <input_ogv> <output_omv | output_dir> [--refer ref.omv] [--mode N] [--flags 0x...]
```

#### Parameters

| Parameter | Description |
|---|---|
| `--x` | **Extract** mode. Strips the SiglusEngine wrapper and writes a plain `.ogv` file. |
| `--a` | **Analyze** mode. Prints detailed header information including outer header fields, TableA, and TableB frame metadata, plus parsed Theora stream info such as FPS, keyframe granule shift, pixel format, and frame size when available. |
| `--c` | **Create** mode. Wraps a plain `.ogv` with the SiglusEngine `.omv` header. |
| `--refer <ref.omv>` | Copy the header `mode` and TableB `flags_hi24` from an existing `.omv` reference. Useful for matching the exact header of the original. Overridden by `--mode` / `--flags` if both are specified. |
| `--mode N` | Override the `mode` field (header offset `0x28`). Accepts decimal or `0x...` hex. |
| `--flags 0xXXXXXX` | Override the TableB `flags` high 24 bits. Accepts a single value or a comma-separated range spec like `0-9:0x1A2B3C00,10-:0x00000000`. |

Directory input for `-v --x` recursively scans for `.omv` files and preserves the relative directory structure in the output. For `-v --c`, the second argument is interpreted as a directory if it already exists as a directory, ends with a path separator, or has no extension; to write to a specific file, give an explicit path ending in `.omv`.

#### Preparing `.ogv` Inputs

Prepare `.ogv` inputs for `-v --c` as video-only Theora streams. For engines that require `yuv444p`, set the pixel format explicitly; FFmpeg defaults may choose another format such as `yuv420p`.

Use an FFmpeg build that includes `libtheora`.

```bash
ffmpeg -i input_video -map 0:v:0 -an -vf "format=yuv444p" -c:v libtheora -q:v 8 output.ogv
```

`-q:v 8` is only a sample quality setting; adjust it as needed.

#### Examples

```bash
# Extract all .omv files in a directory to .ogv
siglus-ssu -v --x /path/to/movie/ /path/to/ogv_out/

# Analyze a single .omv
siglus-ssu -v --a /path/to/op.omv

# Repackage an .ogv back to .omv using original header metadata
siglus-ssu -v --c /path/to/op_translated.ogv /path/to/op_translated.omv --refer /path/to/op_original.omv

# Repackage with manual mode and flags
siglus-ssu -v --c /path/to/op.ogv /path/to/op.omv --mode 10 --flags 0x19DC00
```

---

### `-p` / `--patch` — Patch `SiglusEngine.exe`

Patch mode modifies selected binary values inside `SiglusEngine.exe`.

#### Syntax

```bash
siglus-ssu -p --altkey <input_exe> <input_key> [-o output_exe] [--inplace]
siglus-ssu -p --lang (cjk | cjk-path) <input_exe> [-o output_exe] [--inplace] [--allow-partial]
siglus-ssu -p --info <input_exe>
siglus-ssu -p --loc (0 | 1) <input_exe> [-o output_exe] [--inplace]
```

#### Parameters

| Parameter | Description |
|---|---|
| `<input_exe>` | Path to `SiglusEngine.exe` to patch. Symbolic links are rejected; pass the real executable path. |
| `<input_key>` | **(`--altkey` only)** Source for the new 16-byte key. Accepts a file path to `key.txt`, `暗号.dat`, `SiglusEngine*.exe`, or `Scene.pck`; a `key=bytes` literal; or an `angou=text` literal. Directories are not accepted. This positional form is only valid with `--altkey`. |
| `-o`, `--output` | Output executable path. Defaults to `<stem>_alt.exe`, `<stem>_CJK.exe`, `<stem>_CJKPATH.exe`, `<stem>_LOC0.exe`, or `<stem>_LOC1.exe`. An existing symbolic-link output is rejected. |
| `--inplace` | Overwrite the input executable directly. Cannot be combined with `-o` / `--output`. |
| `--allow-partial` | Only for `--lang`. Write the available changes even when the current engine build lacks part of the selected preset. By default every preset component is required. |
| `--lang cjk` | Patch font charset, locale, and `system.get_language` for CJK display while keeping `Gameexe.dat`, `Scene.pck`, and `savedata` paths unchanged. |
| `--lang cjk-path` | Same as `cjk`, and retarget active path references to `GameexeZH.dat`, `SceneZH.pck`, and `savedata_zh`. |
| `--info` | Print patchable `ALTKEY`, `LANG`, and `LOC` information and exit without writing a file. |
| `--loc 0` | Disable region detection by replacing the matched top-level check routine with an always-pass stub. |
| `--loc 1` | Re-enable region detection only for executables previously disabled by this tool's function-stub patch. |

#### Language Presets

`--lang cjk` changes Japanese/CJK charset compare slots to `0x86`, relocates the active locale string to `chinese`, and relocates the active language code string to `zh`.

`--lang cjk-path` performs the same changes, then writes the official ZH path strings into an unused PE string cave and repoints active references to them. The original short strings may remain in the file as unreferenced data.

Language presets are complete transactions by default: every required charset, locale, language-code, and selected path component must be patchable or already have the target value. Unsupported builds report missing components without writing output. Successful output is written through a temporary file and atomically replaced; use `--allow-partial` only when retaining the available subset is intentional.

#### Charset Slots

`--info` reports every matched `80 78 17 xx` charset compare site instead of requiring exactly two slots. The common values are:

- `0x00` (`ANSI_CHARSET`): ANSI font search.
- `0x80` (`SHIFTJIS_CHARSET`): Shift-JIS font search.
- `0x86` (`GB2312_CHARSET`): GB2312 font search.

The CJK presets patch only recognized Japanese/CJK slots. If no such slot is present, strict mode reports the charset component as missing instead of guessing another slot.

#### Examples

```bash
siglus-ssu -p --altkey /path/to/SiglusEngine.exe /path/to/key.txt -o /path/to/SiglusEngine_patched.exe
siglus-ssu -p --lang cjk /path/to/SiglusEngine.exe
siglus-ssu -p --lang cjk-path /path/to/SiglusEngine.exe --inplace
siglus-ssu -p --info /path/to/SiglusEngine.exe
siglus-ssu -p --loc 0 /path/to/SiglusEngine.exe
siglus-ssu -p --loc 1 /path/to/SiglusEngine.exe --inplace
```

#### Output

```
Input : /path/to/SiglusEngine.exe
Mode  : lang:cjk-path
SHA256(before): abc123...
SHA256(after) : def456...
Applied changes: N bytes
 - LANG charset: jp/shift-jis -> chs/gbk (1 bytes)
 - LANG string SceneZH.pck (N bytes)
 - LANG Scene: Scene.pck -> SceneZH.pck (N bytes)
Written: /path/to/SiglusEngine_CJKPATH.exe
```

`--info` prints active code-referenced language/path slots:

```
Input : /path/to/SiglusEngine.exe
SHA256: abc123...
ALTKEY: 0xAA, 0xBB, ...
LANG charset1: 0x201BC8=0x00 (eng/ansi)
LANG charset2: 0x2BE1D3=0x80 (jp/shift-jis)
LANG presets: cjk, cjk-path
LANG Locale : japanese @ 0x677C94 refs=1
LANG Code   : ja @ 0x64FC6C refs=3
LANG Scene  : Scene.pck @ 0x66D208 refs=2
LANG Save   : savedata @ 0x66D814 refs=1
LANG Gameexe: Gameexe.dat @ 0x672C4C refs=1
LOC   : enabled (original function, func=0x22BF20)
```

---

### `-t` / `--tutorial` — Build a Static Tutorial Graph

Builds a static dialogue graph JSON from the compiled scene data inside a `Scene.pck`. The output is designed for broad inspection rather than perfect VM-complete execution. It keeps all narrow-sense dialogue lines, prefers soundness over aggressive guessing, and only emits static edges that can be justified without reconstructing dynamic runtime state.

The command also writes a self-contained `tutorial_viewer.html` next to the JSON and then tries to open that viewer in the default browser. Auto-open is best-effort and may fail harmlessly.

#### Syntax

```bash
siglus-ssu -t <input_pck> [output_json]
```

#### Parameters

| Parameter | Description |
|---|---|
| `<input_pck>` | Input `Scene.pck` archive to analyze. |
| `[output_json]` | Optional output path for the generated tutorial graph JSON. If omitted, the default is `<input_name>.tutorial.json` next to the input `.pck`. |

#### Output

The command writes:

- a tutorial graph JSON file
- a sibling `tutorial_viewer.html`

The JSON contains graph metadata plus per-node payload lines and per-edge static relations. The viewer can open the JSON directly, auto-load it when launched from `-t`, and inspect one connected graph at a time.

#### What the Graph Represents

- Node payloads are built from narrow-sense dialogue lines, defined here as all type-1 strings from `-m` style extraction.
- Speaker attribution is intentionally conservative. When the source does not clearly expose a reliable speaker, the payload line is kept without forcing a guessed name.
- The graph is allowed to have multiple disconnected components.

#### Static-Edge Policy

This mode intentionally favors correctness over maximal reach:

- Included: direct static control-flow and statically-resolved scene-transfer edges that can be justified from disassembly without VM execution.
- Excluded: dynamic string-built targets, runtime-only dispatch, and ambiguous helper / scheduler promotion that would risk false edges.

As a result, the graph is a sound under-approximation: it may miss some real dynamic continuations, but it should avoid inventing misleading ones.

#### Viewer Notes

The generated viewer supports:

- drag-and-drop JSON loading
- graph selection when multiple disconnected graphs exist
- force-based layout with directional edge particles
- node inspection with scene name and natural source line numbers
- search by dialogue / options, node number, scene name, or `scene @ line`
- English / Simplified Chinese UI toggle and a light / dark theme toggle

#### Example

```bash
# Write Scene.tutorial.json next to Scene.pck and try to open the viewer
siglus-ssu -t /path/to/Scene.pck

# Write to a custom JSON path
siglus-ssu -t /path/to/Scene.pck /path/to/out/tutorial.json
```

### `test` — Round-Trip Compile Test

Tests whether one `.pck` file, or all `.pck` files directly under a directory, can be extracted and compiled back. A byte-identical rebuild is `EXACT`; a different `.pck` with unchanged normalized scene payload semantics is `PAYLOAD_SAME`.

This mode is intended for `.pck` archives that contain embedded original-source data. If a `.pck` has no OS section, it is skipped because there is no original `.ss` source to recompile.

#### Syntax

```bash
siglus-ssu test [--serial] <input_pck|input_dir>
```

`--serial` disables parallel compilation during the rebuild step. Rebuilds are parallel by default.

#### Workflow

For each `.pck`, the command:

1. analyzes the header and checks whether `original_source_header_size` indicates an OS section;
2. extracts the archive into a temporary test directory;
3. recompiles the extracted source in place, trying `const-profile` 0, then 1, then 2 until one profile produces `EXACT` or `PAYLOAD_SAME`;
4. checks whether the rebuilt `.pck` is byte-identical to the original, and otherwise compares them with normalized `-a --payload` semantics;
5. removes all temporary test files.

#### Output

Step log lines report status only. A completed file is `EXACT` when the original and rebuilt `.pck` bytes match exactly, or `PAYLOAD_SAME` when the bytes differ but the normalized payload comparison succeeds. `PASS` is not a result category. The `total` line and final summary include timings for `analyze`, `extract`, `compile`, `payload`, and `cleanup` when those steps run. If compilation falls back across profiles, the `compile` timing includes every attempted profile.

Compile errors are kept quiet while fallback profiles remain. If every profile fails, the command prints the captured compile output for the failed attempts and marks that file as `FAIL`.

The final summary reports total counts, and lists only failed files with their total time and step timings.

The command exits with `0` when at least one file is `EXACT` or `PAYLOAD_SAME` and no file fails. It exits with `1` when any file fails, or when all discovered files are skipped.

#### Example

```bash
siglus-ssu test /path/to/Scene.pck
siglus-ssu test /path/to/pck_dir/
```

<a id="siglusss-language-spec"></a>

## SiglusSceneScript Language Specification (SiglusSS; as Defined by `-c`)

This section treats the current `siglus-ssu -c` compiler as the normative definition of the **SiglusSceneScript language** (abbreviated **SiglusSS language**), rather than as an implementation note. Unless stated otherwise, “shall”, “shall not”, and “may” are used in their normative sense.

The specification in this section covers the front-end and directory-level link constraints for `.ss` source files together with same-directory `.inc` files under a given `const.py` and `--const-profile`. `const.py` / `--const-profile` affect:

- the set of available form names;
- the built-in property / command set;
- certain extra profile-dependent static restrictions.

They do **not** change the core character preprocessing, lexical structure, scene grammar skeleton, or most static rules given here.

### Conformance principle

An implementation conforming to the current compiler shall, under the same `const-profile`, `.inc` set, input directory, and conditions:

1. accept and reject the same translation units as the current compiler;
2. resolve names, labels, z-labels, properties, commands, and expression forms in the same way;
3. apply the same directory-level linker judgments for uniqueness and completeness of global `.inc #command` implementations;
4. reproduce the implementation quirks explicitly documented here, because they are already part of the current language definition.

### Terms and translation environment

#### Source-file set

A single `.ss` file is not compiled in isolation. Its compilation environment consists of:

- the current `.ss` file;
- all `.inc` files in the same directory;
- the form and built-in element tables supplied by the active `const.py` / `--const-profile`.

Same-directory `.inc` files are processed in **lower-cased filename sort order**.

#### Decoding and line endings

`-c` first decodes each source file according to the source encoding selected by `--charset` or auto-detected by the compiler. During this read, CRLF and lone CR line endings are normalized to `\n`; the CA stage also removes any remaining `\r` before character-level processing. The remaining rules of the SiglusSS language are therefore defined over this normalized LF text stream.

#### Normative terms

- **scene text**: the part of a `.ss` file that is parsed by the ordinary scene grammar, excluding `#inc_start ... #inc_end` regions;
- **scene-local inc region**: the text between `#inc_start` and `#inc_end` inside a `.ss` file, parsed by the `.inc` declaration language;
- **global `.inc` environment**: the declaration, replacement, and name-set environment produced by all same-directory `.inc` files;
- **well-formed program**: a program accepted by the complete front-end and link constraints defined here.

### Translation phases

For a single `.ss` translation unit, the current compiler can be normalized as follows:

1. read and decode the source text;
2. normalize CRLF / lone CR line endings to `\n`, and remove any remaining `\r`;
3. apply character-level processing to the scene source: comment removal, ASCII upper-case folding outside literals and comments, `#ifdef` / `#elseifdef` / `#else` / `#endif` handling, and extraction of `#inc_start ... #inc_end` regions;
4. analyze the extracted scene-local inc regions as `.inc` text with parent form = `scene`;
5. merge the declarations and replacement environment produced by step 4 into the current file environment;
6. perform replacement expansion on the scene text;
7. run lexical analysis (LA), syntax analysis (SA), semantic analysis (MA), and bytecode generation (BS) on the expanded scene text;
8. when `-c` compiles a whole directory, run the directory-level linker checks after all scene front-end phases finish.

Two consequences are normative:

- scene-level `#ifdef` / `#elseifdef` / `#else` / `#endif` run **before** scene-local inc declarations are analyzed; therefore scene-level conditional compilation cannot see names that are only declared later inside `#inc_start ... #inc_end` in the same `.ss` file;
- the language defined by whole-directory `-c` compilation is strictly larger than “a single `.ss` file passes the front-end”.

### Character-level processing

#### Case folding

Outside string literals, character literals, and comments, ASCII `A` through `Z` are folded to lower case before further processing. Therefore:

- ASCII keywords are case-insensitive;
- ASCII identifiers, labels, and directive names are case-insensitive;
- non-ASCII characters are not case-folded by this step.

#### Comments

Both scene text and `.inc` text accept these comment forms:

- `;` to end of line;
- `//` to end of line;
- `/* ... */` block comments.

`/* ... */` does not nest. An unterminated block comment is ill-formed. Comment openers inside single-quoted and double-quoted literals are ignored.

#### Conditional compilation

Both scene text and `.inc` text support:

```text
#ifdef <word>
#elseifdef <word>
#else
#endif
```

The rules are:

1. `#ifdef` and `#elseifdef` test whether the name belongs to the current `name_set`; they do not evaluate a numeric truth value;
2. the maximum nesting depth is 15; entering depth 16 is an error;
3. unmatched `#else`, `#elseifdef`, and `#endif`, and an unterminated `#ifdef`, are ill-formed;
4. `<word>` is not parsed by the ordinary scene identifier rule but by a wider `word-ex` rule: the first character may be an ASCII letter, a fullwidth/double-byte character, `_`, or `@`, and later characters may additionally include digits.

#### `#inc_start` / `#inc_end`

These directives exist only during scene-file character processing. Their rules are:

1. `#inc_start` begins collection of a scene-local inc region;
2. `#inc_end` ends that region;
3. the current implementation treats this as a Boolean state rather than a nesting counter, so nested `#inc_start` blocks are **not supported**;
4. an unmatched `#inc_end` or an unterminated `#inc_start` is ill-formed.

#### Source metadata comment

If the first line of the file begins with this byte prefix:

```text
// #SCENE_SCRIPT_ID = dddd
```

where `dddd` is a four-digit decimal number, the compiler records those four digits as scene metadata; any later text on that first line is ignored for this metadata read. It does not alter the core grammar or static semantics, but it is part of the accepted source format.

### Lexical structure

#### White space and newlines

White-space characters are:

- space;
- TAB;
- newline.

A newline is not a statement terminator. The SiglusSS language has no semicolon statement terminator.

#### Identifiers

Ordinary scene identifiers follow:

```text
identifier ::= identifier-start { identifier-continue }
identifier-start ::= "_" | "$" | "@" | ascii-letter
identifier-continue ::= identifier-start | digit
```

where `ascii-letter` is effectively `a ... z` after case folding.

The reserved keywords are:

```text
command  property  goto  gosub  gosubstr  return
if  elseif  else  for  while  continue  break
switch  case  default
```

#### Labels and z-labels

A label token begins with `#`:

```text
label-token ::= "#" { "_" | ascii-letter | digit }
z-label-token ::= "#z" digit [digit [digit]]
```

Normatively:

1. an ordinary label may be empty at the lexical level, so a lone `#` still tokenizes as an ordinary label;
2. only a spelling of exactly `#z` followed by 1 to 3 decimal digits is a z-label;
3. `#z0`, `#z00`, and `#z000` are all z-labels; `#z1234` is not;
4. redefinition, missing definitions, and the mandatory presence of `#z0` are enforced later.

#### Integer literals

Three forms of integer literal are accepted:

```text
decimal ::= digit { digit }
binary  ::= "0b" { "0" | "1" }
hex     ::= "0x" { hex-digit }
```

Their semantics are:

1. they are accumulated as **signed 32-bit integers** during lexing;
2. overflow wraps as `i32`;
3. the minus sign is not part of the literal; it is a unary operator.
4. a bare `0b` or `0x` is accepted and yields `0`.

#### Character and string literals

Single-quoted and double-quoted literals may not cross a physical line. The only accepted escape spellings are:

- `\\`
- `\n`
- `\'` inside single-quoted literals, or `\"` inside double-quoted literals

In double-quoted literals, `\n` becomes a newline. In single-quoted literals, the current lexer accepts `'\n'` but yields the character `n`, not a line feed; this quirk is normative. A single-quoted literal shall yield **exactly one character** according to that lexer rule; otherwise it is ill-formed. A character literal lexes as `VAL_INT`. A double-quoted literal lexes as `VAL_STR`.

#### Fullwidth / double-byte bare strings

Any consecutive run of characters that `_iszen()` classifies as double-byte or fullwidth, excluding `【` and `】`, lexes directly as `VAL_STR`. Therefore both of the following produce string tokens:

```text
"Hello"
你好
```

This is also why speaker-name brackets such as `【角色名】` and bare dialogue lines work without quotes.

#### Delimiters and operators

The delimiters are:

```text
.  ,  :  (  )  [  ]  {  }  【  】
```

Assignment operators are statement-only, not expression operators:

```text
=  +=  -=  *=  /=  %=  &=  |=  ^=  <<=  >>=  >>>=
```

Expression precedence, from lowest to highest, is:

| Level | Operators | Associativity |
|---|---|---|
| 1 | `||` | left |
| 2 | `&&` | left |
| 3 | `\|` | left |
| 4 | `^` | left |
| 5 | `&` | left |
| 6 | `==`, `!=` | left |
| 7 | `>`, `>=`, `<`, `<=` | left |
| 8 | `<<`, `>>`, `>>>` | left |
| 9 | `+`, `-` | left |
| 10 | `*`, `/`, `%` | left |
| unary | `+`, `-`, `~` | prefix |

### The `.inc` declaration language

Global `.inc` files and scene-local inc regions share the same declaration language. After comment removal and case folding, they shall consist only of white space and the following declarations:

```text
inc-unit ::= { inc-decl }
inc-decl ::= replace-decl
           | define-decl
           | define-s-decl
           | macro-decl
           | property-decl
           | command-decl
           | expand-decl
```

#### Name-extraction rules

Names in `.inc` are not extracted by one universal identifier rule. Instead:

- `#replace` / `#define` names stop at space, TAB, or newline;
- `#define_s` names stop at TAB or newline, so they **may contain spaces**;
- `#property` names stop at space, colon, TAB, or newline;
- `#command` names stop at space, `(`, colon, TAB, or newline;
- `.inc #property` and `#command` names may therefore exceed the ordinary scene identifier character set;
- macro names must begin with `@`;
- all of these declarations share one `name_set`: redeclaring an existing name is ill-formed, and every successful declaration immediately inserts its name into `name_set`, thereby affecting later `#ifdef` / `#elseifdef` decisions.

#### `#replace`, `#define`, and `#define_s`

```text
replace-decl   ::= "#replace"  name replacement-text
define-decl    ::= "#define"   name replacement-text
define-s-decl  ::= "#define_s" name-s replacement-text
```

`replacement-text` is extracted as follows:

1. skip leading white space after the name;
2. read until the next unescaped `#` or end of file;
3. fold embedded newlines into spaces;
4. trim trailing spaces and TABs;
5. `##` denotes a literal `#`;
6. nested `#ifdef` / `#elseifdef` / `#else` / `#endif` are allowed inside it.

Expansion semantics are:

- `#replace`: after replacement, the scan position advances to the end of the inserted text, so the inserted text is not immediately rescanned at that same position;
- `#define` and `#define_s`: after replacement, the scan position remains at the original position, so the inserted text is immediately eligible for further expansion.

The replacement system also has two normative details:

1. within a single replacement tree, matching uses **longest-prefix search**;
2. when the default replacement tree and a temporary added tree both match at the same position, the current implementation chooses the candidate whose `name` field is lexicographically larger, not by declaration order or by a global cross-tree longest-match rule; a conforming implementation shall reproduce this behavior.

The current compiler also has a protection threshold against non-progressing infinite expansion loops. Hitting that protection is ill-formed.

#### `#macro`

```text
macro-decl ::= "#macro" macro-name ["(" macro-param {"," macro-param} ")"] replacement-text
macro-name ::= "@" <non-space-sequence>
macro-param ::= param-name ["(" default-text ")"]
```

Rules:

1. a macro is a textual substitution, not a semantic call;
2. actual arguments and defaults are handled as raw text, then textually expanded under the current replacement environment before substitution;
3. if parentheses are present, the parameter list shall be non-empty; empty `()` is rejected;
4. argument splitting is parenthesis-depth aware, and commas or parentheses inside string and character literals do not participate in outer-level splitting;
5. the macro body is expanded with a temporary replacement tree for the macro parameters; after the final result is inserted, scanning advances past that inserted result, so it is not immediately rescanned at the same position.

#### `#property`

```text
property-decl ::= "#property" name [":" form-name ["[" integer-literal "]"]]
```

Rules:

1. the default form is `int`;
2. `void` shall not be used as a property form;
3. the array suffix is allowed only for `intlist` and `strlist`;
4. the array size shall be a decimal integer constant, not an arbitrary expression.

#### `#command`

```text
command-decl ::= "#command" name ["(" inc-arg {"," inc-arg} ")"] [":" form-name]
inc-arg ::= form-name ["(" default-literal ")"]
default-literal ::= signed-int-literal | double-quoted-string
```

Rules:

1. the default return form is `int`;
2. `.inc #command` parameters carry forms and defaults only; they do not carry parameter names;
3. if parentheses are present, the parameter list shall be non-empty; empty `()` is rejected;
4. once one parameter has a default, every later parameter shall also have a default;
5. the syntax allows `int` and `str` defaults;
6. however, the current BS stage auto-fills omitted defaults only for remaining `int` parameters. Omitting a later string default still causes a BS-stage error, and this limitation is therefore part of the present language definition.

#### `#expand`

```text
expand-decl ::= "#expand" replacement-text
```

`#expand` immediately expands its text under the current replacement environment and inserts the expanded result back into the current `.inc` source, after which `.inc` declaration analysis continues from the insertion point.

### Scene grammar

After removing scene-local inc regions, ordinary scene text is analyzed by the following skeleton:

```text
program ::= { sentence }

sentence ::= label-stmt
           | z-label-stmt
           | command-def
           | property-def
           | goto-stmt
           | return-stmt
           | if-stmt
           | for-stmt
           | while-stmt
           | continue-stmt
           | break-stmt
           | switch-stmt
           | call-or-assign-stmt
           | name-stmt
           | text-stmt
```

#### Core statements

```text
label-stmt   ::= label-token
z-label-stmt ::= z-label-token

command-def  ::= "command" identifier ["(" [property-def {"," property-def}] ")"] [":" form] block
property-def ::= "property" identifier [":" form]

goto-stmt ::= "goto" label-target
            | "gosub" [arg-list] label-target
            | "gosubstr" [arg-list] label-target

return-stmt ::= "return"
              | "return" "(" exp ")"

if-stmt ::= "if" "(" exp ")" block
            { "elseif" "(" exp ")" block }
            [ "else" block ]

for-stmt ::= "for" "(" { sentence } "," exp "," { sentence } ")" block
while-stmt ::= "while" "(" exp ")" block
continue-stmt ::= "continue"
break-stmt ::= "break"

switch-stmt ::= "switch" "(" exp ")" "{" { case-clause } [ default-clause ] "}"
case-clause ::= "case" "(" exp ")" { sentence }
default-clause ::= "default" { sentence }

call-or-assign-stmt ::= elm-exp [ assign-op exp ]
name-stmt ::= "【" string-token "】"
text-stmt ::= string-token

block ::= "{" { sentence } "}"
label-target ::= label-token | z-label-token
assign-op ::= "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "&=" | "|=" | "^=" | "<<=" | ">>=" | ">>>="
```

Particular points to preserve:

1. `switch` / `case` / `default` use **no colon**; `case(exp)` is followed directly by a sentence sequence;
2. the three `for` clauses are separated by commas, not semicolons;
3. the initializer and loop clauses of `for` are not expressions but “zero or more sentences”;
4. `name-stmt` contains exactly one string token;
5. a standalone string token is itself a legal text statement.

#### Forms, element expressions, and argument lists

```text
form ::= form-name ["[" exp "]"]
arg-list ::= "(" [arg {"," arg}] ")"
arg ::= exp | identifier "=" exp

elm-exp ::= element { "." element | "[" exp "]" }
element ::= identifier [arg-list]
```

Supplementary rules:

1. `form-name` shall be present in the active form table;
2. named and positional arguments may be mixed syntactically; after parsing, named arguments are moved to the tail of the argument sequence while preserving the relative order within the positional and named subsets;
3. `form[exp]` in scene `property` and `command` parameter declarations only requires the index expression to have form `int`; unlike `.inc #property`, the current implementation does not preserve that size as true array metadata for call-local properties.

#### Expressions

```text
simple-exp ::= "(" exp ")"
             | "[" exp {"," exp} "]"
             | goto-exp
             | literal
             | elm-exp

goto-exp ::= "goto" label-target
           | "gosub" [arg-list] label-target
           | "gosubstr" [arg-list] label-target

literal ::= integer-literal | string-token | label-token
```

Additionally:

- a list literal `[...]` shall contain at least one element; an empty list `[]` is not accepted;
- `goto`, `gosub`, and `gosubstr` may appear both as statements and as expressions inside larger expressions.

### Name lookup and form rules

#### Root-name lookup order

Root names are resolved in the order:

```text
call  ->  scene  ->  global
```

where:

- `call` is the current command call frame;
- `scene` is the current scene namespace;
- `global` includes global `.inc` declarations together with profile-supplied built-ins.

Further resolution of a chain such as `a.b[c].d(...)` depends on the form of the preceding segment. The reachable member set is therefore parameterized by the current form table.

#### Reference forms for properties

When an element chain resolves to a property, its expression form is promoted to a reference form:

- `int` -> `intref`
- `str` -> `strref`
- `intlist` -> `intlistref`
- `strlist` -> `strlistref`

Therefore the left-hand side of an assignment shall be an element expression that resolves to a reference form.

#### Special fallback from unresolved bare name to string

If a simple expression satisfies all of the following:

1. it is an `elm-exp` containing exactly **one segment**;
2. that segment has no argument list;
3. name lookup fails;
4. the name contains neither `@` nor `$`;

then the compiler rewrites it to a string literal of the same spelling instead of reporting an unknown element. This rule is part of the language definition, not an error-recovery heuristic.

### Types and static constraints

#### Unary and binary operators

The current implementation accepts these principal form rules:

1. unary `+`, `-`, and `~`: operand shall be `int` or `intref`; result is `int`;
2. when both operands are `int` / `intref`, `+ - * / % == != > >= < <= && || & | ^ << >> >>>` are valid and yield `int`;
3. when both operands are `str` / `strref`:
   - `+` yields `str`;
   - `== != > >= < <=` yield `int`;
4. `str` / `strref` times `int` / `intref` with `*` yields `str`;
5. the reverse `int * str` is invalid;
6. assignment operators are not expressions and appear only in `call-or-assign-stmt`.

#### Assignment

An assignment shall satisfy:

1. the left-hand side is a reference form;
2. `intref` accepts `int` and `intref`;
3. `strref` accepts `str` and `strref`;
4. other reference forms require strict match with the right-hand side.

#### Statement-level constraints

1. `property` statements shall appear only inside a `command` body; top-level `property` is syntactically recognized but semantically ill-formed;
2. conditions of `if`, `for`, and `while` shall be `int` or `intref`;
3. the `switch` condition shall be `int`, `intref`, `str`, or `strref`, and each `case` value shall belong to the same integer family or string family as the condition;
4. the form of `goto` as an expression is `void`; `gosub` is `int`; `gosubstr` is `str`;
5. `continue` and `break` used outside loops are rejected at the BS stage;
6. certain commands marked by the active profile as selection-related shall not appear in conditions, ordinary arguments, goto arguments, or index expressions;
7. `name-stmt` emits a name-display event, and `text-stmt` emits a text-display event and consumes a read-flag slot.

#### Matching command definitions to declarations

A scene `command` definition may be either:

1. a purely scene-local command; or
2. the implementation of a global `.inc #command` declaration.

When a scene `command` implements a global `.inc #command`, the current compiler checks:

- return form equality;
- positional parameter count equality;
- positional parameter form equality.

It does **not** require:

- parameter-name equivalence between the scene definition and the `.inc` declaration;
- default-value equivalence between the scene definition and the `.inc` declaration.

Therefore the current language definition matches global `.inc #command` implementations by return form and positional-parameter form sequence, not by parameter names or defaults.

#### Current extent of `return` checking

The current compiler does not perform an additional independent check that `return(exp)` has a form consistent with the command’s declared return form. Call-site type reasoning still follows the command declaration. A conforming implementation shall reproduce this current behavior.

#### Named arguments

Whether named arguments are accepted depends on whether the callee signature provides a named-argument mapping. For calls that accept named arguments, the compiler matches by name and checks the target slot form; an unknown named argument or a form mismatch is an error.

### Whole-file and directory-level constraints

#### Labels and z-labels

A scene file shall satisfy:

1. ordinary labels are not redefined;
2. z-labels are not redefined;
3. every referenced label and z-label is defined;
4. `#z0` is present;
5. every scene-local `command` declaration is eventually defined in the same file.

#### Directory-level linking of global `.inc #command`

When `-c` compiles and packs a whole directory, the following shall also hold:

1. global `.inc #command` declarations participate in the directory-level command table;
2. each such global `.inc #command` shall be implemented by **exactly one** scene;
3. if more than one scene implements the same command, the linker reports it as “defined more than once”;
4. if no scene implements it, the linker reports it as “is not defined”.

One current implementation quirk is also normative: the missing-definition pass runs only after the linker has seen at least one scene `command` label anywhere in the directory. In a degenerate directory with zero scene `command` definitions overall, the current linker does not emit the “is not defined” error.

Therefore, an implementation that reproduces only the single-file front-end but not these directory-level constraints is not fully conforming to the present `-c` language definition.

## Tips and Troubleshooting

### Unexpected Tokens During Compilation

If text intended as one argument contains argument delimiters such as commas or parentheses, write it as a double-quoted string:

```
# The comma splits this into additional arguments
mes(【Hero】, Wait, I need to think about this.)

# Quoted form
mes(【Hero】, "Wait, I need to think about this.")
```

### Mixed-Form String Multiplication

The official compiler writes the right-hand form of a plain binary `*` expression as if it were the left operand (`exp_1`). This project intentionally uses the semantically natural right operand form (`exp_2`) instead.

The problematic syntax is an ordinary binary `*` expression used as a value, where the left operand is string-like and the right operand is integer-like after dereferencing. Examples include `set_namae("ABC" * 3)`, `set_namae(s[0] * a[0])`, and `s[0] = "ABC" * 3`.

If you need a source form that compiles to the same output under both the official `exp_1` behavior and this project's `exp_2` behavior, rewrite it through a string reference and `*=`. This can stay on one source line:

```ss
s[0] = "ABC" s[0] *= 3 set_namae(s[0])
```

Do not rewrite it as `s[0] = s[0] * 3`, because that still uses the same problematic ordinary binary `*` expression form.
