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
   - [init — Download Required Constants](#init--download-required-constants)
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
5. [SiglusSceneScript Language Specification (SiglusSS; as Defined by `-c`)](#siglusss-language-spec)
6. [Tips and Troubleshooting](#tips-and-troubleshooting)

---

## Overview

**SiglusSceneScriptUtility** (abbreviated **SSSU** or invoked as **siglus-ssu**) is a command-line utility for working with files used by the **SiglusEngine** visual novel engine. It faithfully reproduces the engine's SceneScript compilation pipeline and provides a comprehensive set of tools for:

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

After installation, you **must** run `init` once to download the required `const.py` runtime constants:

```bash
siglus-ssu init
```

> **Note:** Python 3.12 or later is required. The package ships with a prebuilt native Rust extension for performance-critical operations. If no wheel is available for your platform (e.g., Termux on Android), you will need to build the Rust extension from source.
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

   If this machine's user data directory does not yet contain a verified `const.py`, you still need to run initialization once before using any mode other than `init`:

   ```bash
   uv run siglus-ssu init
   ```

---

## General Usage

```
siglus-ssu [-h] [-V | --version] [--legacy] [--const-profile N] (-lsp | init | -c | -x | -a | -d | -k | -e | -m | -g | -s | -v | -p) [args]
```

### Global Options

| Option | Description |
|---|---|
| `-h`, `--help` | Show the help message and exit. |
| `-V`, `--version` | Show the program version and exit. |
| `--legacy` | Disable the Rust native acceleration and use the pure Python fallback implementation. Useful for debugging. |
| `--const-profile N` | Select one of the built-in `const.py` profiles (`0`-`2`, default: `0`). Use a non-default profile only when targeting an engine/compiler variant whose form or element tables differ from the default profile. |

### Command Aliases

The CLI also accepts a few convenience aliases:

- `siglus-ssu help` behaves the same as `siglus-ssu --help`
- `siglus-ssu version` behaves the same as `siglus-ssu --version`
- `siglus-ssu --init ...` behaves the same as `siglus-ssu init ...`

### Getting Help

```bash
# Show the global help message, listing all modes
siglus-ssu --help

# LSP mode has its own help page
siglus-ssu -lsp --help

# Other modes currently do not have dedicated mode-specific help pages;
# this still falls back to the global help output.
siglus-ssu -c --help
```

---

## Modes Reference

### `init` — Download Required Constants

Downloads the `const.py` file containing engine-specific constants (opcode tables, key derivation parameters, etc.) from the project's GitHub repository.

**Before first use on a given machine, you must ensure that the user data directory contains a verified `const.py`. For PyPI installations this usually means running `init` once; even when running from source, you still need `init` if that user directory does not already contain a valid `const.py`.**

#### Syntax

```
siglus-ssu init [--force | -f] [--ref <git-ref>]
```

#### Parameters

| Parameter | Description |
|---|---|
| `--force`, `-f` | Overwrite an existing `const.py` even if one already exists. |
| `--ref <git-ref>` | Download `const.py` from a specific Git branch, tag, or commit hash. By default, `init` tries the current package version's release ref first, then matching tag names. |

`init` requires network access to the GitHub API. If `--force` is not specified and `const.py` already exists at the target location, the command will not re-download but will directly load and verify the existing file.

After download, `const.py` is verified against a built-in SHA-512 allowlist. The built-in default ref mapping only tracks the current supported package version; explicit `--ref` values still work as long as they ultimately resolve to the same allowlisted `const.py` content.

#### Examples

```bash
# Basic initialization (downloads const.py for the current package version)
siglus-ssu init

# Overwrite an existing const.py
siglus-ssu init --force

# Download const.py from a specific tagged release
siglus-ssu init --ref v0.2.1
```

---

### `-lsp` — Start the Language Server

Starts a standard **stdio JSON-RPC / Language Server Protocol** service for the **SiglusSceneScript language** (abbreviated **SiglusSS language**) and for `.inc` declaration files.

#### Syntax

```
siglus-ssu -lsp [--serial]
```

#### Parameters

- `--serial`: Disable the default parallel workspace scanning and use serial scanning instead.

#### Notes

- Official entrypoint: `siglus-ssu -lsp`
- By default, workspace-wide symbol and link scans run in parallel; use `--serial` to force serial scanning when needed
- Current capabilities: semantic tokens, diagnostics, completion, hover, go to definition, find references, prepare rename, rename, document symbols, and live same-directory `.inc` overlay refresh for `.ss` analysis; the current semantic token categories include dialogue text, system elements, and speaker names
- The language service reuses the same `-c` compiler pipeline stages (`CA`, `LA`, `SA`, `MA`, `BS`) wherever they apply; semantic classification comes from that compiler-aligned analysis, while the LSP layer recovers source ranges and packages the results as semantic tokens, locations, and edits
- The current project scope is directory-based, matching the present `-c` model for `.inc` / `.ss` joint analysis and global `.inc #command` linking
- The service itself is editor-agnostic and can be consumed by VS Code, Neovim, Emacs, Sublime Text, Kate, Helix, or any other client that can launch an external stdio LSP server
- The recommended editor architecture is: fallback lexical grammar, commands, tasks, and UI in the editor extension; semantic highlighting, lint, navigation, references, and rename delegated to `siglus-ssu -lsp`

---

### `-c` / `--compile` — Compile Scripts

Compiles a directory of `.ss` SceneScript source files into a `.pck` file. During compilation, individual scene `.dat` files are first generated in a temporary directory, then in the normal mode they are linked and packed into the final `Scene.pck`. The compilation pipeline faithfully reproduces the official SiglusEngine build system, including LZSS compression, per-script string-table shuffling, and `暗号.dat`-based encryption.

It also supports compiling `Gameexe.ini` → `Gameexe.dat` independently via `--gei`.

#### Syntax

```
# Standard compilation
siglus-ssu -c [options] <input_dir> <output_pck | output_dir>

# Compile only Gameexe.dat from an existing Gameexe.ini
siglus-ssu -c --gei <input_dir | Gameexe.ini> <output_dir>

# Compile with shuffle seed brute-force
siglus-ssu -c --test-shuffle [seed0] <input_dir> <output_pck | output_dir> <test_dir>
```

#### Parameters

| Parameter | Description |
|---|---|
| `<input_dir>` | Directory containing `.ss` source files, optionally alongside `.inc`, `.ini` / `Gameexe.ini`, and `暗号.dat`. |
| `<output_pck \| output_dir>` | Output path. If the path ends with `.pck`, the file is written there. If the argument already exists and is a directory, or ends with a path separator, a `Scene.pck` is created inside it. Other non-existent paths that do not end with `.pck` are currently also interpreted as an output file path. |
| `--debug` | Keep intermediate temporary files (`.dat`, `.lzss`, etc.) after compilation. Also prints per-stage timing statistics. |
| `--charset ENC` | Force source file encoding. Accepted values: `jis`, `cp932`, `sjis`, `shift_jis` (all equivalent to CP932/Shift-JIS), or `utf8`, `utf-8`. If omitted, the encoding is auto-detected. |
| `--no-os` | Skip the OS (Original Source) embedding stage. The `Scene.pck` is still generated and written out normally, but no original source files are embedded inside it. Does not affect encryption or compression of the scripts themselves. |
| `--dat-repack` | Instead of compiling `.ss` scripts, scan `input_dir` for existing `.dat` files, copy them, and pack them directly into a `.pck` file. Useful for packing already-compiled scripts. It can only be combined with `--no-os` and/or `--no-lzss`. Cannot be combined with `--test-shuffle`. |
| `--no-angou` | Disable LZSS compression and XOR encryption. Sets `header_size = 0`. Useful for debugging or for engines without encryption. |
| `--no-lzss` | Disable only the LZSS stage while keeping the usual script encryption/header behavior. This matches the official "easy link" style output. |
| `--serial` | Disable multi-process parallel compilation and force the compile stage to run serially. Parallel compilation is enabled by default. |
| `--max-workers N` | Maximum number of parallel worker processes. Only effective while parallel compilation is enabled; defaults to auto. |
| `--lzss-level N` | LZSS compression level, from `2` (fast, large) to `17` (slow, smallest). Default: `17`. |
| `--set-shuffle SEED` | Set the initial MSVC-compatible `rand()` seed for the per-script string table shuffle. Accepts decimal or `0x...` hex. Default: `1`. Implies `--serial`. |
| `--tmp <tmp_dir>` | Use a specific persistent temporary directory. When provided, an MD5 cache (`_md5.json`) is maintained inside this directory to enable **incremental compilation** — only changed `.ss` files are recompiled on subsequent runs. |
| `--test-shuffle [seed0]` | Brute-force scan all possible 32-bit MSVC `rand()` seeds to find the one that reproduces the string table order in `<test_dir>`. Optionally start the scan at `seed0`. |
| `--gei` | Only run the `Gameexe.ini` → `Gameexe.dat` compilation stage, writing a fixed filename `Gameexe.dat` into the output directory. |

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

- **Auto-encoding detection:** If `--charset` is not specified, the utility scans `.ss`, `.inc`, and `.ini` files for a UTF-8 BOM or Japanese characters. If found, `utf-8` is used; otherwise, `cp932` (Shift-JIS) is assumed.
- **Incremental compilation:** When `--tmp` is specified, the compiler caches MD5 hashes of all `.ss` and `.inc` files. On the next run, only files whose hash has changed (or whose `.dat` is missing) are recompiled. If any `.inc` file changes, a full recompile is triggered.
- **Shuffle seed:** All official game builds shuffle the string table in each `.dat` using an MSVC-compatible `rand()` seed, though some use a seed other than the default `1`. You do not need to match this for normal translation work — the engine reads strings correctly regardless of order. The `--set-shuffle` and `--test-shuffle` options are only needed if you want a byte-for-byte identical binary output.

---

### `-x` / `--extract` — Extract Files

Extracts a `.pck` scene file into a timestamped directory containing decoded scene `.dat` files and any embedded original source files, or restores the `Gameexe.ini` plaintext from a binary `Gameexe.dat`.

#### Syntax

```bash
# Extract a .pck file
siglus-ssu -x [--disam] <input_pck> [output_dir]

# Batch-disassemble and decompile `.dat` files from a directory
siglus-ssu -x --disam <input_dir> [output_dir]

# Restore Gameexe.ini from Gameexe.dat
siglus-ssu -x --gei <Gameexe.dat | input_dir> [output_dir]
```

#### Parameters

| Parameter | Description |
|---|---|
| `<input_pck>` | Path to the `.pck` file to extract. |
| `<input_dir>` | Path to a directory scanned for `.dat` files when `--disam` is enabled. Only the immediate `.dat` files in that directory are processed. |
| `<output_dir>` | Directory where extracted files will be written. Optional for all `-x` modes. If omitted, output defaults to the input file directory, or to the input directory itself when the input is a directory. |
| `--disam` | With `.pck` input, also write `<scene>.dat.txt` disassembly plus reconstructed `decompiled/<scene>.ss` files and `decompiled/__decompiled.inc`. With directory input, scan only that directory's immediate `.dat` files and write `.dat.txt` plus `decompiled/*.ss` into `<output_dir>`. Cannot be combined with `--gei`. Non-scene `.dat` files are skipped. |
| `--gei` | Instead of extracting a `.pck`, decode a `Gameexe.dat` binary back to a `Gameexe.ini` plaintext file. The input can be the `.dat` file itself or its parent directory. Automatically detects a nearby `暗号.dat`, `key.txt`, or `SiglusEngine*.exe` to derive the decryption key. |

With `.pck` input, extracted files are written into `output_YYYYMMDD_HHMMSS/`. When embedded original sources are present, they are restored there alongside the decoded scene `.dat` files. A `--disam` run also prints total disassembly, decompile-hints, and decompile timing summaries.

The current decompiler is experimental. Treat `decompiled/*.ss` as inspection output, not as a reliable reconstruction of the original source or a guaranteed round-trip input for release work.

#### Examples

```bash
# Extract Scene.pck into the translation_work directory
siglus-ssu -x /path/to/Scene.pck /path/to/translation_work/

# Extract Scene.pck next to the input file
siglus-ssu -x /path/to/Scene.pck

# Extract with `.dat` disassembly and decompiled `.ss`
siglus-ssu -x --disam /path/to/Scene.pck /path/to/translation_work/

# Batch-disassemble and decompile the `.dat` files in one directory
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
# Analyze a single file
siglus-ssu -a [--disam] [--readall] [--payload] <input_file>

# Count dialogue units in a .pck only and write per-file CSV
siglus-ssu -a --word <input_pck> [output_csv]

# Compare two files of the same type
siglus-ssu -a [--payload] <input_file_1> <input_file_2>

# Analyze or derive the exe_el key from 暗号.dat / SiglusEngine.exe / directory
siglus-ssu -a <path_to_暗号.dat | SiglusEngine.exe | dir> --angou

# Analyze or compare Gameexe.dat
siglus-ssu -a --gei <Gameexe.dat> [Gameexe.dat_2]
```

#### Parameters

| Parameter | Description |
|---|---|
| `<input_file>` | Path to the file to analyze. Supported extensions: `.pck`, `.dat`, `.gan`, `.sav`, `.cgm`, `.tcr`. |
| `[input_file_2]` | Optional second file for comparison. If both files are the same type, a structural comparison is performed; if types differ, each file is analyzed separately. |
| `--disam` | When analyzing a `.dat` file, write a human-readable disassembly to `<scene>.dat.txt` alongside the input `.dat`, and also emit reconstructed `decompiled/<scene>.ss` and `decompiled/__decompiled.inc`. Prints total disassembly, decompile-hints, and decompile timing summaries before the command finishes. The decompiler output is still experimental and should not be treated as a reliable source-of-truth. |
| `--readall` | For `read.sav` files only: set all read-flag bits to `1` (marking every scene as read). Overwrites the input file in-place. |
| `--word` | For `.pck` only: skips normal structural analysis, counts dialogue units for each decoded scene `.dat` and each embedded `.ss` source file, prints the per-file counts, and writes them to CSV. If `[output_csv]` is omitted, the CSV is written as `<input_pck_stem>.word.csv` next to the input `.pck`. |
| `--payload` | For `.pck` and `.dat` comparisons, additionally compare normalized decoded/decompressed `scn_bytes` semantics. This ignores string-pool ID differences when the resolved text is the same, but still treats text changes and other scene-bytecode changes as different. It is more expensive than a plain structural comparison, but helps distinguish scene-content changes from container-only differences. |
| `--angou` | Parse the input as a `暗号.dat` (or `SiglusEngine*.exe`, or directory containing one) and derive and print the `exe_el` key (the 16-byte key shown in `key.txt` format). |
| `--gei` | Analyze or compare `Gameexe.dat` files instead of general binary files. |

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

# Compare two versions of Scene.pck — reports file additions, removals, and changes
siglus-ssu -a /path/to/Scene_original.pck /path/to/Scene_translated.pck

# Compare two Scene.pck files by normalized decoded `scn_bytes` semantics
siglus-ssu -a --payload /path/to/Scene_original.pck /path/to/Scene_translated.pck

# Write .dat disassembly to disk for inspection
siglus-ssu -a --disam /path/to/script.dat

# Set all read flags in read.sav to 1
siglus-ssu -a --readall /path/to/savedata/read.sav

# Derive the exe_el key from 暗号.dat
siglus-ssu -a /path/to/暗号.dat --angou

# Derive the exe_el key from the SiglusEngine executable directly
siglus-ssu -a /path/to/SiglusEngine.exe --angou

# Derive the exe_el key from a game directory (auto-detects 暗号.dat or exe)
siglus-ssu -a /path/to/game_dir/ --angou
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
...
```

If an embedded or adjacent `暗号.dat` is available, `.pck` analysis also appends a trailing `=== 暗号.dat ===` block and prints its first line, matching the compile-mode summary style.


#### Word Count Output (`-a --word`)

`-a --word` prints one row per decoded scene `.dat` and one row per embedded `.ss` source file. The count rule is as follows:

- Han, Hiragana, Katakana, and Bopomofo count as `1` per character
- Hangul counts by contiguous word run
- Other letters and numbers count by contiguous word run
- Internal `'`, `’`, `-`, and `_` keep a non-Asian run together when both sides are alphanumeric
- Internal `.`, `,`, `/`, and `:` keep a numeric run together when both sides are decimal digits
- Punctuation, whitespace, emoji, and other symbols count as `0`

The CSV uses:

- `type` — `dat` or `ss`
- `path` — per-file relative path inside the `.pck`
- `status` — `ok` or `failed`
- `dialogue_lines` — number of counted dialogue entries
- `dialogue_count` — total counted dialogue units

---

### `-d` / `--db` — Export and Compile `.dbs` Databases

Works with `.dbs` binary database files, which store tabular data (rows and columns) used by the engine for configuration, scenario flow, or other structured data.

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
siglus-ssu -d --c --test-shuffle [skip0] <expected.dbs> <input.csv> <output.dbs | output_dir>
```

#### Parameters

| Parameter | Description |
|---|---|
| `--x` | **Extract** mode: export `.dbs` → `.csv`. |
| `--a` | **Analyze** mode: dump structural info. With two arguments, compare two `.dbs` files. |
| `--c` | **Compile** mode: create `.dbs` from `.csv`. |
| `--type N` | Override the `m_type` field of the generated `.dbs` (integer). Default: `1`. |
| `--set-shuffle SEED` | Set the initial MSVC `rand()` seed for the internal string order. Accepts decimal or `0x...` hex. Default: `1`. |
| `--test-shuffle [skip0]` | Brute-force the MSVC `rand()` skip count needed to match the padding pattern at the end of a reference `.dbs`. Optionally start from `skip0`. Single-file mode only. |

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

#### CSV Format

The exported CSV uses UTF-8 BOM encoding with CRLF line endings and is compatible with Microsoft Excel. The first two rows are the `#DATANO` and `#DATATYPE` header rows, followed by data rows.

- `#DATANO` row: the first column is fixed to `#DATANO`, and the remaining columns are the call numbers of each column header.
- `#DATATYPE` row: the first column is fixed to `#DATATYPE`, and the remaining columns are the data type markers of the corresponding columns; the main types you will see are `S` (string) and `V` (numeric / other 32-bit unit).
- Data rows: the first column of each row is that row's row call number, and the remaining columns correspond to the column order defined by the first two rows.

Special characters in string values are escaped:

| Escape Sequence | Meaning |
|---|---|
| `\\` | Literal backslash |
| `\n` | Newline |
| `\r` | Carriage return |
| `\t` | Tab |

---

### `-k` / `--koe` — Collect Voice Files by Character

Scans compiled scene data from a `.pck`, a single scene `.dat`, or a directory tree of scene `.dat` files, reads KOE-related calls from disassembly traces, matches them against `.ovk` voice archive entries, and extracts the corresponding `.ogg` audio files. In normal mode, files are grouped into per-character subdirectories.

In normal mode, the command also generates a `koe_master.csv` manifest listing all found KOE entries with their character name, dialogue text, and call-site location. When scanning a `.pck` directly, call-sites are reported as `Scene.pck!scene.dat:line`. After processing, the tool also computes the total duration of **referenced** voice files only; entries written under `unreferenced/` are explicitly excluded from that total. If a particular `.ogg` duration cannot be read, CSV output still succeeds, but that item is counted under `Duration failed`.

#### Syntax

```
siglus-ssu -k [--stats-only] <scene_input> <voice_dir> <output_dir>
siglus-ssu -k [--stats-only] --single KOE_NO <voice_dir> <output_dir>
```

#### Parameters

| Parameter | Description |
|---|---|
| `<scene_input>` | Path to `Scene.pck`, a single scene `.dat`, or a directory tree of scene `.dat` files. Required in normal mode; not used with `--single`. |
| `<voice_dir>` | Path to the directory containing `.ovk` voice archive files (typically named `z0001.ovk`, `z0002.ovk`, etc.). Can also be a direct path to a single `.ovk` file. In directory mode, only `.ovk` files in that directory itself are scanned; the search is not recursive. |
| `<output_dir>` | Directory where extracted `.ogg` files will be written. In normal mode, `koe_master.csv` is also written there. With `--single`, the extracted file is written directly under `<output_dir>`. |
| `--stats-only` | Prints the summary and does not write any `.ogg` files. In normal mode it still writes `koe_master.csv`; with `--single`, no CSV is written. |
| `--single KOE_NO` | Only extracts the specified global KOE number. In this mode, no scene input is required, no `koe_master.csv` is generated, no character-name or `unreferenced` subdirectories are created, and the output file is written directly as `<output_dir>/KOE(XXXXXXXXX).ogg`. |

#### Output Structure

```
<output_dir>/
  koe_master.csv           — Master manifest of all KOE entries
  <CharacterName>/         — One subdirectory per character name
    KOE(000000001).ogg
    KOE(000000002).ogg
    ...
  unreferenced/            — Entries in .ovk not referenced by any scanned scene
    KOE(000000003).ogg
    ...
```

With `--single`, the output structure becomes:

```
<output_dir>/
  KOE(123456789).ogg
```

#### Examples

```bash
# Collect all voice files directly from Scene.pck
siglus-ssu -k /path/to/Scene.pck /path/to/voice/ /path/to/voice_out/

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
| `koe_no` | The global KOE number (scene_no × 100000 + entry_no). Empty for call-sites where the OVK entry was not found. |
| `character` | Character name inferred from `CD_NAME` events and inline voice metadata in the scene trace. |
| `text` | Dialogue text inferred from `CD_TEXT` events and inline voice metadata in the scene trace. |
| `callsite` | Semicolon-separated list of `filename:line` locations where this KOE is called, or `Scene.pck!scene.dat:line` when scanning a `.pck` directly. |

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

The example above shows normal-mode output. `Stats only` and `Single KOE` are only shown when the corresponding option is used. With `--single`, scene-scanning and CSV-related lines are omitted.

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
siglus-ssu -m --disam <path_to_dat | path_to_dir>

# Apply translated string list back to compiled .dat file(s)
siglus-ssu -m --disam-apply <path_to_dat | path_to_dir>
```

#### Parameters

| Parameter | Description |
|---|---|
| `<path_to_ss \| path_to_dir>` | A single `.ss` file or a directory of `.ss` files. Exactly one path argument is required. |
| `<path_to_dat \| path_to_dir>` | A single `.dat` file or a directory. Exactly one path argument is required. |
| `--apply`, `-a` | Apply a `.ss.csv` text map back to the corresponding `.ss` file in-place. The `.ss.csv` must already exist alongside the `.ss` file. |
| `--disam` | Export the string list from a compiled `.dat` to a `.dat.csv` file alongside the `.dat`. Works on encrypted, LZSS-compressed, or raw `.dat` files. When given a directory, `.dat` files are recursively scanned, and `Gameexe.dat` and `暗号.dat` are automatically excluded. |
| `--disam-apply` | Apply a `.dat.csv` translated string list back to the compiled `.dat` in-place. `--apply`, `--disam`, and `--disam-apply` are mutually exclusive. |

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

3. **Apply the translated text map:**

   ```bash
   siglus-ssu -m --apply /path/to/scripts/chapter1.ss
   # or equivalently:
   siglus-ssu -m -a /path/to/scripts/chapter1.ss
   ```

   After applying, the tool automatically performs a **bracket content fix** on the modified file: it strips spurious double-quote characters and leading spaces that appear inside `【】` name brackets (a common artifact when translated text is pasted without removing surrounding quotes). The number of fixed items is reported to stderr.

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
| `replacement` | The translation. Initially identical to `original`. Fill this in. |

Special characters in `original` and `replacement` are escape-encoded:

| Escape | Meaning |
|---|---|
| `\\` | Literal backslash |
| `\n` | Newline |
| `\r` | Carriage return |
| `\t` | Tab |

#### `.dat.csv` Format

| Column | Description |
|---|---|
| `index` | String index (`str_id`) in the compiled string table. |
| `kind` | String kind: `1 = dialogue`, `2 = speaker name`, `3 = other text`. |
| `original` | The original string value (escape-encoded). |
| `replacement` | The replacement string value. Initially identical to `original`. |

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

> **Note:** Except for `--a` (pure analysis mode), all `.g00` extract, merge, create, and update operations currently require [Pillow](https://pillow.readthedocs.io/) (`pip install pillow`).

#### Syntax

```
# Analyze a .g00 file (no Pillow required)
siglus-ssu -g --a <input_g00>

# Extract .g00 to PNG/JPEG files
siglus-ssu -g --x <input_g00 | input_dir> <output_dir>

# Merge multiple .g00 files (or cuts) into a single PNG
siglus-ssu -g --m <input_g00[:cutNNN]> <input_g00[:cutNNN]> [...] [--o <output_dir>]

# Create a new .g00 from image files, or update from an explicit reference .g00
siglus-ssu -g --c [--type N] [--refer <ref_g00 | ref_dir>] <input_png | input_jpeg | input_json | input_dir> [output_g00 | output_dir]
```

#### Parameters

| Parameter | Description |
|---|---|
| `--a` | **Analyze** mode. Prints type, canvas size, and LZSS stats; for type2, also prints detailed information for up to the first 50 cuts. |
| `--x` | **Extract** mode. Decodes each `.g00` and writes PNG or JPEG files; for type2, also exports a round-trippable `.type2.json` sidecar. |
| `--m` | **Merge** mode. Composites multiple `.g00` images or cuts into one PNG. |
| `--c` | **Create/update** mode. Without `--refer`, creates a new `.g00`. With `--refer`, updates image payload using the referenced `.g00` as the base. |
| `--o <output_dir>`, `-o`, `--output`, `--output-dir` | (Merge mode only) Optional output directory for the merged PNG. If omitted, the file is written to the current working directory. |
| `--type N`, `--t N` | (Create mode only) In create mode, force the output `.g00` type. In update mode, override the expected reference `.g00` type for validation. |
| `--refer <ref_g00 \| ref_dir>` | (Create mode only) Use an existing `.g00` as the explicit base for update semantics. Single-file input accepts either a `.g00` file or a directory; directory input requires a reference directory. If the output path is omitted in update mode, single-file input defaults to writing back to the reference `.g00`, and directory input defaults to writing back to the reference directory. |
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

# Create a new type0 .g00 from a PNG (output optional)
siglus-ssu -g --c /path/to/new_bg.png /path/to/game_bg.g00

# Omit output path: create <input_basename>.g00 next to the input image
siglus-ssu -g --c /path/to/new_bg.png

# Create a new type3 .g00 from a JPEG
siglus-ssu -g --c /path/to/op.jpeg /path/to/op.g00

# Create a type2 .g00 from a JSON layout
siglus-ssu -g --c --type 2 /path/to/char_face.type2.json /path/to/char_face.g00

# Batch create type2 .g00 files from a directory of extracted/rebuild layouts
siglus-ssu -g --c --type 2 /path/to/layout_dir/ /path/to/out_g00/

# Update an existing .g00 using an explicit reference
siglus-ssu -g --c /path/to/new_bg.png /path/to/game_bg.g00 --refer /path/to/original_bg.g00

# Batch update using a reference directory
siglus-ssu -g --c /path/to/updated_pngs/ /path/to/out_g00/ --refer /path/to/original_g00/
```

Directory input for `-g --x` **recursively** scans for `.g00` files, but the current implementation writes all output directly to the same `output_dir` without preserving the original subdirectory structure; if identically named resources exist in different subdirectories, later same-named outputs are skipped because the target already exists.

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
- `source_rect` is optional. If omitted, the full source image is used. When both are present, they must have the same width and height.
- `center` is optional per cut and defaults to `default_center` or `(0,0)`.
- Recommended practice for strict, reproducible rebuilds: keep one JSON file beside the extracted PNG set and edit only the PNG pixels or the explicit rect/center fields you actually intend to change.

#### Type2 Extract / Rebuild Asset Convention

When `-g --x` extracts a type2 `.g00`, it always exports a JSON sidecar next to the images:
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

# Step 3: rebuild by passing the JSON file directly
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
siglus-ssu -s --x <input_dir | input_file> <output_dir> [--trim <path_to_Gameexe.dat>]

# Analyze an audio file (structural info)
siglus-ssu -s --a <input_file.(nwa | ovk | owp)>

# Create / re-encode audio files
siglus-ssu -s --c <input_ogg | input_dir> <output_dir>

# Play one looped BGM using Gameexe.dat loop points
siglus-ssu -s --play <input_file.(owp | ogg)> <path_to_Gameexe.dat>
```

#### Parameters

| Parameter | Description |
|---|---|
| `--x` | **Extract** mode. Decodes `.owp` → `.ogg`, `.nwa` → `.wav`, `.ovk` → individual `.ogg` files. |
| `--a` | **Analyze** mode. Prints detailed structural header information for one audio file. |
| `--c` | **Create** mode. Encodes `.ogg` files → `.owp`, or groups of numbered `.ogg` files → `.ovk` archives. Directory input recursively scans for `.ogg` files and preserves the relative directory structure in the output. |
| `--play` | **Play** mode. Plays one `.owp` or `.ogg` BGM using the `#BGM.*` loop-point table from `Gameexe.dat`. Playback starts at `start`, then loops the `repeat` → `end` region indefinitely through **ffplay**. Requires `ffplay` to be on the system `PATH`. |
| `--trim <Gameexe.dat>` | (Extract mode only) Read the `#BGM.*` loop-point table from `Gameexe.dat` and trim each `.owp` to its loop region using **ffmpeg**. Requires `ffmpeg` to be on the system `PATH`. This option only affects `.owp` extraction; `.nwa`/`.ovk` files are not trimmed. |

#### Examples

```bash
# Decode all audio in a directory
siglus-ssu -s --x /path/to/bgm/ /path/to/ogg_out/

# Decode a single .ovk voice archive
siglus-ssu -s --x /path/to/z0001.ovk /path/to/ogg_out/

# Decode .owp BGM files and trim to loop region using Gameexe.dat
siglus-ssu -s --x /path/to/bgm/ /path/to/ogg_out/ --trim /path/to/Gameexe.dat

# Analyze an .nwa file header
siglus-ssu -s --a /path/to/bgm01.nwa

# Analyze an .ovk archive table
siglus-ssu -s --a /path/to/z0001.ovk

# Analyze an .owp file
siglus-ssu -s --a /path/to/bgm01.owp

# Play one .owp BGM from its start point and loop forever using Gameexe.dat
siglus-ssu -s --play /path/to/bgm01.owp /path/to/Gameexe.dat

# Re-encode .ogg files back to .owp
siglus-ssu -s --c /path/to/translated_ogg/ /path/to/owp_out/
```

#### OVK Extraction Naming

When extracting a `.ovk` with multiple entries, output files are named:
- `<basename>.ogg` — if only one entry.
- `<basename>_<entry_no>.ogg` — if multiple entries (e.g., `z0001_0.ogg`, `z0001_1.ogg`).

#### OVK Creation Naming

When creating `.ovk` from a directory, files named `<basename>_<N>.ogg` (where `N` is an integer) are only grouped into a single `<basename>.ovk` when at least two files share the same basename. If a group contains only one numerically-suffixed file, the current implementation treats it as a regular single-file input and produces an `.owp`. Files without a numeric suffix are also individually encoded as `.owp`.

#### `.owp` Trim Details

The `--trim` option reads the Gameexe.dat BGM table (entries formatted as `#BGM.N = "...", "filename", start, end, repeat`) and calls **ffmpeg** to trim each decoded `.ogg` to the samples between `repeat` and `end`. This is useful for extracting seamlessly-loopable background music.

#### Loop Playback Details

The `--play` option reads the same Gameexe.dat BGM table and matches entries by input basename. It accepts `.owp` and plain `.ogg` input, starts playback at `start`, and then loops the `repeat` → `end` sample region indefinitely through **ffplay**. If `end` is `-1` or extends past the decoded Ogg length, playback treats EOF as the loop end. This mode is intended for BGM loop preview and does not support `.nwa` or `.ovk`.

Directory input for `-s --x` also recursively scans subdirectories and preserves the relative directory structure in the output.

---

### `-v` / `--video` — Work with `.omv` Video Files

Provides tools for analyzing, extracting, and recompiling `.omv` video files. The `.omv` format is an Ogg container (`.ogv`) with a proprietary SiglusEngine wrapper header.

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

Directory input for `-v --x` recursively scans for `.omv` files and preserves the relative directory structure in the output. For `-v --c`, the second argument is interpreted as a directory if it already exists as a directory, ends with a path separator, or has no extension; to write to a specific file, give an explicit `.omv`-extension path.

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

Applies binary patches to `SiglusEngine.exe`. Supports three patch operations:

- **`--altkey`**: Replace the embedded `exe_el` decryption key with a different one.
- **`--lang`**: Apply a language preset (`chs` or `eng`) or a custom JSON-specified mapping to redirect the engine to a different `.pck` file, save directory, and character encoding.
- **`--loc`**: Toggle the built-in Japan-only region check (`0` = disable/force pass, `1` = enable/restore original check).

#### Syntax

```
# Patch the embedded exe_el key
siglus-ssu -p --altkey <input_exe> <input_key> [-o output_exe] [--inplace]

# Apply a language patch
siglus-ssu -p --lang (chs | eng | <json>) <input_exe> [-o output_exe] [--inplace]

# Toggle region detection
siglus-ssu -p --loc (0 | 1) <input_exe> [-o output_exe] [--inplace]
```

#### Parameters

| Parameter | Description |
|---|---|
| `<input_exe>` | Path to `SiglusEngine.exe` to patch. |
| `<input_key>` | **(--altkey only)** The new 16-byte key. Accepts: a literal like `0xA9, 0x86, ...`; `key.txt`; `暗号.dat`; `SiglusEngine*.exe`; or a directory (auto-derives key). |
| `-o`, `--output` | Path for the output patched executable. Defaults to `<stem>_alt.exe` (altkey), `<stem>_CHS.exe` / `<stem>_ENG.exe` (lang), or `<stem>_LOC0.exe` / `<stem>_LOC1.exe` (loc). |
| `--inplace` | Overwrite the input file directly instead of writing to a new path. If both `-o`/`--output` and `--inplace` are given, `--inplace` takes precedence. |
| `--lang chs` | Apply the built-in Simplified Chinese preset. |
| `--lang eng` | Apply the built-in English preset. |
| `--lang <json>` | Apply a custom JSON-specified patch (see below). Here `<json>` is an **inline JSON string**, not a path to a JSON file. |
| `--loc 0` | Disable region detection by forcing the Japan-only check to return success. |
| `--loc 1` | Enable region detection by restoring the original Japan-only check. |

#### Language Patch Presets

**`--lang chs`** makes these changes:
- Sets `lfCharSet` to `0x86` (GBK/GB2312 Chinese).
- Replaces `Scene.pck` → `Scene.chs`, `savedata` → `savechs`, `japanese` → `chinese`, `Gameexe.dat` → `Gameexe.chs`.

**`--lang eng`** makes these changes:
- Sets `lfCharSet` to `0x00` (ANSI/Latin).
- Replaces `Scene.pck` → `Scene.eng`, `savedata` → `saveeng`, `japanese` → `english`, `Gameexe.dat` → `Gameexe.eng`.

#### Custom JSON `--lang` Configuration

```json
{
  "charset": 0,
  "suffix": "ENG",
  "replace": {
    "Scene.pck": "Scene.eng",
    "savedata": "saveeng"
  },
  "skip_standalone": ["savedata"]
}
```

| JSON Field | Description |
|---|---|
| `charset` | Target `lfCharSet` value. Accepts `0` / `"eng"` (ANSI), `128` / `"jp"` (Shift-JIS), `134` / `"chs"` (GBK), or any integer. |
| `suffix` | Suffix used for the default output filename (e.g., `"ENG"` → `SiglusEngine_ENG.exe`). |
| `replace` | Object mapping old string → new string (UTF-16LE in-place replacement). The new string must not be longer than the old. |
| `skip_standalone` | List of old strings to skip when they appear surrounded by NUL bytes (i.e., when they appear isolated in memory rather than as part of a path). |

#### Examples

```bash
# Patch the exe_el key from a key.txt file
siglus-ssu -p --altkey /path/to/SiglusEngine.exe /path/to/key.txt -o /path/to/SiglusEngine_patched.exe

# Patch using a literal 16-byte key
siglus-ssu -p --altkey /path/to/SiglusEngine.exe "0xA9, 0x86, 0x3F, 0x12, 0x5E, 0xC1, 0x78, 0x04, 0xBB, 0xA1, 0xF2, 0x93, 0xD4, 0x7E, 0x60, 0x55"

# Patch using the key derived from 暗号.dat
siglus-ssu -p --altkey /path/to/SiglusEngine.exe /path/to/暗号.dat --inplace

# Apply the English language patch
siglus-ssu -p --lang eng /path/to/SiglusEngine.exe

# Apply the CHS language patch in-place
siglus-ssu -p --lang chs /path/to/SiglusEngine.exe --inplace

# Apply a custom JSON language patch
siglus-ssu -p --lang '{"charset":0,"suffix":"ENG","replace":{"Scene.pck":"Scene.eng"}}' /path/to/SiglusEngine.exe

# Disable region detection
siglus-ssu -p --loc 0 /path/to/SiglusEngine.exe

# Re-enable region detection in-place
siglus-ssu -p --loc 1 /path/to/SiglusEngine.exe --inplace
```

#### Output

The patch command prints a summary of changes to stdout before writing the output file:

```
Input : /path/to/SiglusEngine.exe
Mode  : lang:eng
SHA256(before): abc123...
SHA256(after) : def456...
Applied changes: N bytes
 - lfCharSet: -> 0x00 (N bytes)
 - Scene.pck -> Scene.eng (N bytes)
 - savedata -> saveeng (N bytes)
 - japanese -> english (N bytes)
 - Gameexe.dat -> Gameexe.eng (N bytes)
Written: /path/to/SiglusEngine_ENG.exe
```

For `--loc`, the summary also prints the previous and new switch states:

```
Input : /path/to/SiglusEngine.exe
Mode  : loc:0
SHA256(before): abc123...
SHA256(after) : def456...
LOC(before): enabled
LOC(after) : disabled
Applied changes: 3 bytes
 - region detection: enabled -> disabled (3 bytes)
Written: /path/to/SiglusEngine_LOC0.exe
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

Same-directory `.inc` files are processed in **case-folded filename order**.

#### Decoding and line endings

`-c` first decodes each source file according to the selected or detected source encoding. After decoding, every `\r` is removed. The remaining rules of the SiglusSS language are therefore defined over the text stream **after carriage-return removal**.

#### Normative terms

- **scene text**: the part of a `.ss` file that is parsed by the ordinary scene grammar, excluding `#inc_start ... #inc_end` regions;
- **scene-local inc region**: the text between `#inc_start` and `#inc_end` inside a `.ss` file, parsed by the `.inc` declaration language;
- **global `.inc` environment**: the declaration, replacement, and name-set environment produced by all same-directory `.inc` files;
- **well-formed program**: a program accepted by the complete front-end and link constraints defined here.

### Translation phases

For a single `.ss` translation unit, the current compiler can be normalized as follows:

1. read and decode the source text;
2. remove `\r`;
3. apply character-level processing to the scene source: comment removal, ASCII upper-case folding outside literals and comments, `#ifdef` / `#elseifdef` / `#else` / `#endif` handling, and extraction of `#inc_start ... #inc_end` regions;
4. analyze the extracted scene-local inc regions as `.inc` text with parent form = `scene`;
5. merge the declarations and replacement environment produced by step 4 into the current file environment;
6. perform replacement expansion on the scene text;
7. run lexical analysis (LA), syntax analysis (SA), semantic analysis (MA), and bytecode generation (BS) on the expanded scene text;
8. when `-c` compiles a whole directory, run the directory-level linker checks after all scene front-end phases finish.

Two consequences are normative:

- scene-level `#ifdef` / `#elseifdef` / `#else` / `#endif` run **before** scene-local inc declarations are analyzed; therefore scene-level conditional compilation cannot see names that are only declared later inside `#inc_start ... #inc_end` in the same file;
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
4. `<word>` is not parsed by the ordinary scene identifier rule but by a wider “word-ex” rule: the first character may be an ASCII letter, a fullwidth/double-byte character, `_`, or `@`, and later characters may additionally include digits.

#### `#inc_start` / `#inc_end`

These directives exist only during scene-file character processing. Their rules are:

1. `#inc_start` begins collection of a scene-local inc region;
2. `#inc_end` ends that region;
3. the current implementation treats this as a Boolean state rather than a nesting counter, so nested `#inc_start` blocks are **not supported**;
4. an unmatched `#inc_end` or an unterminated `#inc_start` is ill-formed.

#### Source metadata comment

If the first line of the file has the form:

```text
// #SCENE_SCRIPT_ID = dddd
```

where `dddd` is a four-digit decimal number, the compiler recognizes it as scene metadata. It does not alter the core grammar or static semantics, but it is part of the accepted source format.

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

Single-quoted and double-quoted literals may not cross a physical line. The only escape sequences are:

- `\\`
- `\n`
- `\'` or `\"`, matching the surrounding quote kind

A single-quoted literal shall yield **exactly one character** after escape processing; otherwise it is ill-formed. A character literal lexes as `VAL_INT`. A double-quoted literal lexes as `VAL_STR`.

#### Fullwidth / double-byte bare strings

Any consecutive run of characters that `_iszen()` classifies as double-byte or fullwidth, excluding `【` and `】`, lexes directly as `VAL_STR`. Therefore both of the following produce string tokens:

```text
"Hello"
你好
```

This is also why speaker names and bare dialogue lines work without quotes.

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
2. actual arguments and defaults are handled as raw text;
3. if parentheses are present, the parameter list shall be non-empty; empty `()` is rejected;
4. argument splitting is bracket-depth aware, and commas or parentheses inside string and character literals do not participate in outer-level splitting;
5. the macro expansion result is fed back into the current replacement flow.

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
3. `form[exp]` in scene `property` and command-parameter declarations only requires the index expression to have form `int`; unlike `.inc #property`, the current implementation does not preserve that size as true array metadata for call-local properties.

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
4. `str` / `strref` times `int` / `intref` yields `str`;
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

Therefore the current language definition matches implementations by return form and positional-parameter form sequence, not by parameter names or defaults.

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

### `const.py is missing. Run 'siglus-ssu init' first.`

You installed from PyPI but have not run the initialization step yet:

```bash
siglus-ssu init
```

### Tokenizer Errors During Compilation

If you get compilation errors about unexpected tokens, check the `.ss` file near the reported line number. Strings containing commas, parentheses, or Japanese quotation marks may need to be wrapped in double quotes:

```
# Before (may cause errors if the comma confuses the parser)
mes(【Hero】, Wait, I need to think about this.)

# After (always safe)
mes(【Hero】, "Wait, I need to think about this.")
```

### Matching the Shuffle Seed

This tool can reproduce `.dat` string-table shuffle positions with an MSVC-compatible `rand()` seed. Translation work usually **does not** need this; you only need to care about the seed when you want byte-for-byte identical output.

If you want a byte-for-byte identical output (e.g., for binary diffing), first try to find the seed:

```bash
siglus-ssu -c --test-shuffle /path/to/src/ /path/to/out/ /path/to/original_dats/
```

If found, compile with the seed:

```bash
siglus-ssu -c --set-shuffle <found_seed> /path/to/src/ /path/to/out/
```

> **Note:** In rare cases, a single initial seed can't fully reproduce the shuffle bit-for-bit. This is likely a result of the original developers using incremental compilation (which we also support via `--tmp`), which changes the file compilation order and consequently the sequence of `rand()` calls.

### Compatibility Note: Mixed-Form String Multiplication

The official compiler writes the right-hand form of a plain binary `*` expression as if it were the left operand (`exp_1`). This project intentionally uses the semantically natural right operand form (`exp_2`) instead.

The problematic syntax is an ordinary binary `*` expression used as a value, where the left operand is string-like and the right operand is integer-like after dereferencing. Examples include `set_namae("ABC" * 3)`, `set_namae(s[0] * a[0])`, and `s[0] = "ABC" * 3`.

If you need a source form that compiles to the same output under both the official `exp_1` behavior and this project's `exp_2` behavior, rewrite it through a string reference and `*=`. This can stay on one source line:

```ss
s[0] = "ABC" s[0] *= 3 set_namae(s[0])
```

Do not rewrite it as `s[0] = s[0] * 3`, because that still uses the same problematic ordinary binary `*` expression form.

### Pillow Not Installed (G00 Mode)

In G00 image mode, all operations except `--a` (pure analysis) currently require [Pillow](https://pillow.readthedocs.io/):

```bash
pip install pillow
```

### ffmpeg / ffplay Not Found (Sound Trim / Play Mode)

The `--trim` feature in sound mode requires `ffmpeg`, and the `--play` feature requires `ffplay`, both installed and available on the system `PATH`. Install them from https://ffmpeg.org/ or via your system package manager.

### Using the Pure Python Fallback

If you encounter issues with the native Rust extension, you can force the pure Python implementation with the `--legacy` flag:

```bash
siglus-ssu --legacy -c /path/to/src/ /path/to/out.pck
```

Note that the pure Python implementation is significantly slower for large projects.

### Termux / Non-prebuilt Platforms

There is no prebuilt wheel available for Termux (Android). You must build the Rust extension manually. This requires installing both the Rust toolchain (`rustup`) and the appropriate `cross`-compilation toolchain for your architecture, which is not an easy process.
