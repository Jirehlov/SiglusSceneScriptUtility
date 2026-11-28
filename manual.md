# SiglusSceneScriptUtility Manual

> **CLI only:** This project supports only the `siglus-ssu` command-line interface, provides no support for direct module imports or calls, and accepts no responsibility for any resulting issues.

**Version:** 0.5.9

**Repository:** [GitHub](https://github.com/Jirehlov/SiglusSceneScriptUtility)

**Chinese Manual:** [manual_cn.md](manual_cn.md)

---

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
   - [Option 1: Install from PyPI](#option-1-install-from-pypi)
   - [Option 2: Install from Source](#option-2-install-from-source)
3. [General Usage](#general-usage)
   - [Global Options](#global-options)
   - [Const Profiles](#const-profiles)
   - [Scene String XOR Multiplier](#scene-string-xor-multiplier)
   - [Command Aliases](#command-aliases)
   - [Getting Help](#getting-help)
4. [Modes Reference](#modes-reference)
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
   - [test — Round-Trip Compile Test](#test--round-trip-compile-test)
5. [SiglusSS Language Specification](#siglusss-language-spec)

---

## Overview

`siglus-ssu` is the command-line interface for compiling and translating SiglusEngine scripts, analyzing game data, editing saves and engine settings, handling media, and serving editors over LSP. Select the game's [const profile](#const-profiles) for scene script operations.

---

## Installation

### Option 1: Install from PyPI

Requires Python 3.12 or later.

```bash
pip install siglus-ssu
```

Platform wheels include Rust acceleration. A pure Python wheel is also available.

### Option 2: Install from Source

Requires Python 3.12+, [uv](https://github.com/astral-sh/uv), and [Rust 1.88+](https://rustup.rs/).

Run these commands from the repository root.

```bash
uv sync
uv run siglus-ssu --help
```

Use `uv run siglus-ssu` for subsequent commands.

---

## General Usage

```
siglus-ssu [-h] [-V|--version] [--legacy] [--legacy-full] [--const-profile N] [--string-xor-multiplier N] (-lsp|-c|-x|-a|-d|-k|-e|-m|-g|-s|-v|-p|test) [args]
```

Native acceleration is used automatically when available.

On Linux and macOS filesystems without hard links, the tool copies staged output into a new file when overwriting is disallowed. A forced stop during the copy can leave that file incomplete.

In-place translation, save edits, and EXE patches check whether the original changed before replacing it. An interrupted update can leave `.siglus-update.lockdir` in the output directory. Remove that directory only when no update is running.

### Global Options

| Option | Description |
|---|---|
| `-h`, `--help` | Show help. |
| `-V`, `--version` | Show the installed version. |
| `--legacy` | Use Python compilation while retaining native helpers. |
| `--legacy-full` | Disable all Rust acceleration. |
| `--const-profile N` | Select the game's profile (`0`–`10`, default `0`). Cannot be combined with `-c --tmp`. An explicit profile disables automatic retries in `test`; `test --decompile` requires one. |
| `--string-xor-multiplier N` | Override the scene-string XOR multiplier. Accepts `0`–`0xFFFF` in decimal or hexadecimal. Profiles `3`, `5`, and `8` default to `0`; all others default to `0x7087`. See [Scene String XOR Multiplier](#scene-string-xor-multiplier). |

Place global options before `--`, on either side of the mode. `--const-profile=N` and `--string-xor-multiplier=N` are also accepted.

### Const Profiles

Profiles select built-in types, element codes, command signatures, and compilation rules. Each row gives the changes from its reference profile and an example engine or game.

Profile `2` is the comparison baseline: scene-string XOR multiplier `0x7087`, local `property` declarations only inside `command`, `&&` higher precedence than `||`, and z-labels `#z0`–`#z999`. It inserts a message block before `global.ruby`, assigns a read flag to `global.koe`, and emits selection blocks for `global.sel`, `global.sel_cancel`, `global.selmsg`, `global.selmsg_cancel`, and `global.sel_image`.

| Profile | Reference | Specific differences | Engine / examples |
|---|---|---|---|
| `0` | `1` | Adds `syscom.msg_back_get_chr_no`, `syscom.msg_back_get_koe_no`, `syscom.msg_back_get_message`, and `syscom.msg_back_get_name`. | Modern SiglusEngine; default. |
| `1` | `2` | Adds types `joypad=1530`, `joystick=1540`, `joytrigger=1550`, and `keyboard=1560`, with keyboard/gamepad input interfaces, button queries, and gamepad-mode settings. Renames `keylist.clear`, `keylist.next`, `keylist.wait`, and `keylist.wait_force` to `__clear`, `__next`, `__wait`, and `__wait_force` in the same type. | Official engine `1.1.140.4`. |
| `2` | — | Baseline rules above; uses `keylist.clear`, `keylist.next`, `keylist.wait`, and `keylist.wait_force`, without profile `1`'s added types/interfaces. | Official engine `1.1.137.0`. |
| `3` | `2` | Uses plain scene strings (XOR multiplier `0`); `global.koe` does not receive a read flag. | TheGodofDeath HD. |
| `4` | `2` | Changes `global.wait_wipe`, `global.koe_wait_key`, `global.exkoe`, `pcmch.wait_key`, and `pcmch.wait_fade_key` from `int` to `void`. Omits selection blocks and the associated selection-command expression restrictions. | Original Rewrite. |
| `5` | `3` | Changes `global.wait_wipe`, `global.exkoe`, `global.exkoe_play_wait_key`, `counter.wait_key`, `pcmch.wait_fade_key`, and `mov.play_wait_key` from `int` to `void`. Does not insert a message block before `global.ruby`. | nanami/Kisaragi. |
| `6` | `2` | Allows call-local `property` declarations outside `command`. | Karumaruka. |
| `7` | `4` | Changes `counter.wait_key` from `int` to `void`; allows call-local `property` outside `command`; treats `&&` and `\|\|` at equal precedence, left to right; limits z-labels to `#z0`–`#z99`. | Rurumi and Yamiiro. |
| `8` | `5` | Uses type codes `frameaction=1212` and `intlistref=11`; allows call-local `property` outside `command`; limits z-labels to `#z0`–`#z99`. Preserves integer-variable references for `global.wipe(key_skip=...)` and `global.mask_wipe(key_skip=...)`; other integer expressions remain values. | Rewrite trial. |
| `9` | `2` | Element code `47` is the `global.world` property of type `worldlist`, replacing the `global.msgbtn` command. | Rewrite Harvest festa! |
| `10` | `0` | Adds mobile UI, touch, network, store, and extension-resource interfaces, including `global.sheet`, `global.touch`, `global.connect`, `global.appstore`, `global.googleplay`, and `global.extend`. Changes `global.message_box` from `void` to `int` and adds named argument `title_str`. | FlixEngine (mobile SiglusEngine). |

Use the same profile when compiling, disassembling, decompiling, and comparing a title. For a PCK with embedded sources, `siglus-ssu test Scene.pck` reports the profile used for a successful rebuild.

Profile `10` uses internal `mobile_*` placeholders for parts of the mobile API.

### Scene String XOR Multiplier

Use `--string-xor-multiplier N` for a title with a different scene-string encoding. `0` selects plain UTF-16LE. Scene-string XOR is independent of compression and outer encryption. `--no-angou` leaves this XOR in effect.

Use the same profile and multiplier for decoding, editing, and rebuilding a title. Each invocation uses one multiplier for all scenes and comparison inputs. The extraction directory does not store the settings. An incorrect multiplier can produce unreadable text.

Changing the multiplier invalidates the `-c --tmp` scene cache. Plain extraction, `--dat-repack`, and `--gei` ignore the multiplier.

Example for plain scene strings

```bash
siglus-ssu --string-xor-multiplier 0 -x --disam /path/to/Scene.pck
siglus-ssu --string-xor-multiplier 0 -m /path/to/extracted/chapter1.dat
siglus-ssu --string-xor-multiplier 0 -m --apply /path/to/extracted/chapter1.dat
siglus-ssu --string-xor-multiplier 0 -c /path/to/source/ /path/to/translated.pck
```

### Command Aliases

`siglus-ssu help` and `siglus-ssu version` are aliases for `--help` and `--version`.

After selecting a mode and required sub-operation, use `--` before positional paths beginning with `-`, for example `siglus-ssu test -- --sample.pck`. All options must precede `--`. For an option value beginning with `-`, use an absolute path or prefix it with `./`.

Write long options in full.

### Getting Help

```bash
siglus-ssu --help
```

Mode-specific `--help` shows the same global help page.

---

## Modes Reference

### `-lsp` — Start the Language Server

```bash
siglus-ssu -lsp [--serial] [--read-sav /path/to/read.sav]
```

The stdio server supports diagnostics, semantic highlighting, completion, hover, definitions, references, rename, and document symbols for `.ss` and `.inc`. Use the same global `--const-profile` as for compilation. Analysis includes unsaved changes and same-directory include files.

| Option | Description |
| --- | --- |
| `--serial` | Disable parallel scene scanning. |
| `--read-sav PATH` | Show saved flag states in hover details and expose read and edit requests to LSP clients. The server can start before the save is available. |

Link checks use the scenes and includes in the document's directory. Push diagnostics refresh file checks as you edit, reusing cached link results. Opening or saving a file, or closing it with unsaved changes, can refresh links. A diagnostic request uses the current source and runs link checks when applicable.

Set `SIGLUS_SSU_LSP_CACHE_DIR` to override the workspace index location. The server rebuilds incompatible indexes.

- Windows uses the first nonempty setting from `%LOCALAPPDATA%\siglus_ssu\lsp-index` and `%APPDATA%\siglus_ssu\lsp-index`.
- The fallback on all systems is `$XDG_CACHE_HOME/siglus_ssu/lsp-index`, or `~/.cache/siglus_ssu/lsp-index` if that variable is empty or unset.

#### Read flags

Flag indices start at `0` in each scene. A saved zero means the engine has yet to mark the flag as read. The engine can commit flags after displaying the content, for example on a wait or text clear. The server matches the scene name and flag count before mapping saved states to the current source. A range points to the text, command, or macro invocation that produced the flag. Multiple flags can share a range.

In the VS Code extension, open **SiglusSS: Read Flags** to enable the mode and select `read.sav`. **Go to First/Last Unread Flag** uses flag order in the current scene. **Go to Previous/Next Unread Flag** uses range starts strictly before or after the cursor, with no wrap. Choose **Mark Flags as Read** or **Mark Flags as Unread** from the editor context menu to update every flag overlapping a selection. If several flags share the cursor position and the selection is empty, choose one from the list.

`siglus/readFlags` accepts `textDocument.uri`. Send the previous `mappingId` and `saveRevision` to reuse mapped ranges. With the same mapping and a changed save, `states` contains the base64-encoded flag bytes. An unchanged report omits ranges and state bytes. Set `verifySave: true` to recheck file contents.

Check `experimental.siglusReadFlags` for write capabilities. `siglus/setReadFlag` takes `index`. `siglus/setReadFlags` takes a nonempty `indices` array. Both take the open document's URI and version in `textDocument`, the current `mappingId`, and a boolean `read`. The server validates the mapping and indices, deduplicates a batch, and checks the original save before replacing it. A successful response includes updated counts, `previousRevision`, and `saveRevision`.

---

### `-c` / `--compile` — Compile Scripts

Compile scene `.ss` files and same-directory `.inc` files into a PCK. The compiler reads the input directory's immediate files, including dot-prefixed names.

#### Syntax

```
siglus-ssu -c [options] <input_dir> <output_pck | output_dir>
siglus-ssu -c --gei <input_dir | Gameexe.ini> <output_dir>
siglus-ssu -c --check <input_dir>
siglus-ssu -c --test-shuffle [seed0] [--csv <seed_csv>] <input_dir> <output_pck | output_dir> <test_dir>
```

#### Parameters

| Parameter | Description |
|---|---|
| `<input_dir>` | At least one named `.ss`, with optional `.inc`, `Gameexe.ini`, `暗号.dat`, and `key.txt` files. `--dat-repack` and `--gei` take other inputs as described below. |
| `<output_pck \| output_dir>` | An existing directory or a path ending in `/` or `\` receives `Scene.pck`. Any other path is treated as the exact output filename. |
| `--check` | Check the selected scene and include sources and validate `Gameexe.ini` when present. The compiler generates scene bytecode in memory and requires exactly one definition for each declared global command. Takes only `<input_dir>` and writes no build artifacts or caches. Incompatible with `--tmp`, `--debug`, `--dat-repack`, `--gei`, `--test-shuffle`, and `--csv`. |
| `--debug` | Keep intermediate files after compilation. Cannot be combined with `--tmp`. |
| `--charset ENC` | Force one encoding for text inputs. Otherwise detect UTF-8 or CP932 per file, with BOM detection for UTF-16/32. Shift-JIS aliases select Windows CP932. Other Python text codecs can be selected explicitly. |
| `--allow-invalid` | Replace undecodable bytes with U+FFFD using the selected or BOM-detected codec. In auto mode without a UTF-16/32 BOM, fall back to UTF-8 replacement only if both strict UTF-8 and CP932 fail. |
| `--no-os` | Omit embedded original sources without changing script encryption or compression. |
| `--dat-repack` | Pack existing scene DATs. Invalid scenes stop publication. Non-scene `Gameexe.dat` and `暗号.dat` are skipped. Same-directory `.inc` files supply package command metadata. The command warns if no includes are found. Supports `--no-os`, `--no-lzss`, `--charset`, `--allow-invalid`, and global options. A valid `key.txt` takes precedence over `暗号.dat`. |
| `--no-angou` | Disable LZSS compression, outer XOR encryption, and original-source embedding. Does not disable scene-string XOR. Cannot be combined with `--tmp`. |
| `--no-lzss` | Disable LZSS compression and original-source embedding, retaining script encryption. Cannot be combined with `--tmp`. |
| `--serial` | Compile scene scripts sequentially. Packaging can use multiple workers. |
| `--max-workers N` | Limit parallel scene compilation to a positive worker count. Automatic allocation per stage is half the available CPUs, limited to 1–16. Python workers on Windows are capped at 61. `--serial` takes precedence. |
| `--set-shuffle SEED` | Set the string-table shuffle seed. Accepts decimal or hexadecimal in `0`–`0xFFFFFFFF`. Defaults to `1` and implies `--serial`. Cannot be combined with `--tmp`. |
| `--tmp <tmp_dir>` | Reuse a directory for incremental compilation. Serial builds reuse cached scenes up to the first change and rebuild the rest to preserve string-table order. Concurrent builds cannot share the cache. Cannot be combined with `--debug`, `--dat-repack`, `--no-angou`, `--no-lzss`, `--set-shuffle`, `--test-shuffle`, `--csv`, `--gei`, or global `--const-profile`. |
| `--test-shuffle [seed0]` | Search from `seed0` (default `0`) through `0xFFFFFFFF` for any continuous seed chain that matches the string indexes of every reference DAT in `<test_dir>`. The compiler matches each source stem to a DAT using the fixed Windows filename case mapping and prefers exact spelling. Requires three paths after the optional seed. If the seed is omitted, a supplied `--set-shuffle` value becomes the search start. Cannot be combined with `--tmp` or `--gei`. |
| `--csv <seed_csv>` | With `--test-shuffle`, publish per-scene initial and final seeds with the linked PCK. A directory target receives `test_shuffle_seeds.csv`. |
| `--gei` | Compile only `Gameexe.ini` to `Gameexe.dat`. The output is a directory. If the input is a directory without `Gameexe.ini`, the command warns and skips output. Cannot be combined with `--tmp` or `--test-shuffle`. |

`Gameexe.ini` is optional in normal compilation too. If absent, `Gameexe.dat` is skipped. An empty INI produces a warning and is compiled. The compiler rejects output paths that refer to its inputs and publishes results only after generating all requested files.

After an interrupted build, check the cache for `_compile.lockdir` and each output file’s resolved parent directory for `.siglus-publish.lockdir`. Remove a leftover lock only after checking that no build is using the directory.

#### Examples

Recompile the extraction directory printed after `Output:`:

```bash
siglus-ssu -c /path/to/translation_work/output_... /path/to/translated.pck
```

Use an incremental cache or limit parallel workers:

```bash
siglus-ssu -c --tmp /path/to/cache /path/to/src /path/to/Scene.pck
siglus-ssu -c --max-workers 2 /path/to/src /path/to/Scene.pck
```

Repack compiled scenes, compile Gameexe alone, or search a shuffle seed:

```bash
siglus-ssu -c --dat-repack /path/to/dat_dir /path/to/repacked.pck
siglus-ssu -c --gei /path/to/src /path/to/out/
siglus-ssu -c --test-shuffle 12345 --csv /path/to/seeds.csv /path/to/src /path/to/out/ /path/to/original_dats/
```

#### Notes

- See the [language specification](#siglusss-language-spec) for source processing and syntax.
- **Key compatibility:** Keys derived from `暗号.dat` or `angou=text` use CP932 and can differ from official Windows conversion. For existing official files, prefer the raw 16-byte key or matching engine executable. For normal compilation, put the raw key in `key.txt` and remove any higher-priority `暗号.dat` from the input directory.
- Incremental builds recompile a scene when its source or cached DAT/LZSS changes or goes missing. Include or setting changes can invalidate the full scene cache. Packaging reuses compressed and encrypted data for unchanged original sources.
- A shuffle search with no matching chain publishes neither PCK nor CSV. Pass the first scene's reported initial seed to `--set-shuffle` to reproduce a matching chain.
- Selected multi-file inputs are checked for collisions under a fixed Windows filename case mapping on all platforms. Automatic file discovery warns on ambiguous names and picks a candidate. Runtime scene names fold ASCII case. Embedded source filenames retain their spelling.

#### Compiling Stats

The final summary reports stage timings and file counts. Compilation and scene compression timings can overlap. `scene_files` is the total scene count. `compiled_scene_files` is the number rebuilt this run. Normal full builds also report source, read-flag, and binary-size statistics.

---

### `-x` / `--extract` — Extract Files

Plain extraction writes decoded scene DATs and embedded sources. `--decompile` writes DATs and reconstructs sources from bytecode.

#### Syntax

```bash
siglus-ssu -x [--disam] [--decompile] <input_pck> [output_dir] [--angou <path|angou=text|key=bytes>]
siglus-ssu -x --disam <input_dir> [output_dir] [--angou <path|angou=text|key=bytes>]
siglus-ssu -x --gei <Gameexe.dat | input_dir> [output_dir] [--angou <path|angou=text|key=bytes>]
```

#### Parameters

| Parameter | Description |
|---|---|
| `<input_pck>` | Scene `.pck` to extract. A valid key is needed to decode encrypted scenes to DATs. |
| `<input_dir>` | With `--disam`, scan immediate `.dat` files, skipping non-scene files. |
| `[output_dir]` | Base output directory. Defaults to the input file's directory, or the input directory itself. PCK extraction creates a timestamped subdirectory. |
| `--disam` | Also write `<scene>.dat.txt` disassembly. Cannot be combined with `--gei`. |
| `--decompile` | With a complete scene PCK, reconstruct `decompiled/<scene>.ss` and, when needed, `decompiled/__decompiled.inc`. Add `--disam` for listings. |
| `--angou VALUE` | Specify a [decryption key source](#decryption-keys). |
| `--gei` | Restore `Gameexe.ini` from `Gameexe.dat` or its parent directory. Directory lookup uses the fixed Windows filename case mapping and warns about case-colliding candidates. If the output already exists, use `Gameexe_1.ini` and so on. |

PCK extraction prints the timestamped subdirectory after `Output:`. It adds numeric suffixes to resolve output collisions and reports filenames the output filesystem cannot represent. Edit embedded sources in that directory and pass it to `-c`.

PCK extraction warns about invalid key sources and continues looking for a usable key. If no key can decrypt the scenes, it extracts any embedded sources and saves the encrypted scene bytes as `<scene>.enc`. Scene disassembly and decompilation require decrypted DATs.

If a scene and its embedded key file are both named `暗号.dat`, the key goes in `.siglus-ssu-keys/`. Compilation and repacking can read the key from there.

Select the profile and string multiplier used by the title. Recompiled output can differ in byte layout. Incomplete disassembly fails decompilation.

FlixEngine scenes use profile `10`. For Flix resource PCKs, use plain `-x` to extract files or plain `-a` to inspect the container.

#### Examples

Extract original sources, disassemble a DAT directory, or restore Gameexe:

```bash
siglus-ssu -x /path/to/Scene.pck /path/to/translation_work/
siglus-ssu -x --disam /path/to/scene_dir/
siglus-ssu -x --gei /path/to/Gameexe.dat /path/to/output/
```

Decompile and verify a profile `0` title. Replace `output_...` with the directory printed by extraction; use the appropriate profile and multiplier for other titles:

```bash
siglus-ssu --const-profile 0 -x --decompile /path/to/Scene.pck /path/to/translation_work/
siglus-ssu --const-profile 0 -c /path/to/translation_work/output_.../decompiled /path/to/rebuilt.pck
siglus-ssu --const-profile 0 -a --payload /path/to/Scene.pck /path/to/rebuilt.pck
```

Check equality using the [payload results](#payload-comparison-results).

---

### `-a` / `--analyze` — Analyze and Compare Files

Analyzes `.pck`, `.dat`, `.gan`, `.sav`, `.cgm`, and `.tcr` files. Two files of the same type are compared; files of different types are analyzed separately. Any analysis failure produces a nonzero exit status.

#### Syntax

```
siglus-ssu -a [--disam] <input_file> [input_file_2] [--angou VALUE]
siglus-ssu -a --payload <input_1.pck> <input_2.pck> [--angou VALUE]
siglus-ssu -a --payload [--disam] <input_1.dat> <input_2.dat> [--angou VALUE]
siglus-ssu -a [--readall|--apply] <input_file.sav>
siglus-ssu -a --read-flags <read.sav> [Scene.pck] [--report-json FILE] [--angou VALUE]
siglus-ssu -a --word <input_pck> [output_csv] [--angou VALUE]
siglus-ssu -a --angou VALUE
siglus-ssu -a --gei <Gameexe.dat> [Gameexe.dat_2] [--angou VALUE]
```

#### Parameters

| Parameter | Description |
|---|---|
| `--disam` | Write disassembly beside each input `.dat` as `<scene>.dat.txt`. Requires one or two scene `.dat` files. For reconstructed `.ss`, use `-x --decompile`. |
| `--readall` | Mark all scenes read in `read.sav`, or unlock engine-managed CG, BGM, and voice collections in `global.sav`. Does not unlock Steam achievements. Creates a non-overwriting `.bak` backup before rewriting the save. |
| `--read-flags` | Export unread flag indices to UTF-8 JSON without modifying the save. Default output: `<save_stem>.flags.json`. An optional PCK validates scene names/counts and supplies original source line numbers. `--angou` requires a PCK. |
| `--report-json FILE` | Set the `--read-flags` report path; also accepts `--report-json=FILE`. Missing parent directories are created. Cannot overwrite the input save, scene PCK, or a file read for its key. |
| `--apply` | Apply sibling `global.txt` to `global.sav`, creating a non-overwriting `.bak` first. Editable entries are `G[n]`, `Z[n]`, `cg_table[n]`, `bgm_table[n]`, and `chrkoe[n].look_flag`; other fields are ignored. |
| `--word` | Count dialogue units per scene `.dat` and embedded `.ss`, print totals, and write CSV. Default output: `<pck_stem>.word.csv` beside the input; a directory target receives that filename. Cannot overwrite an input PCK or a file read for its key. |
| `--payload` | Compare normalized scene payloads for two `.pck` files or two `.dat` files. See [Payload Comparison Results](#payload-comparison-results). |
| `--angou VALUE` | Supply a key source for PCK/DAT/Gameexe processing, or inspect a key without another input. See [Decryption Keys](#decryption-keys). |
| `--gei` | Analyze or compare `Gameexe.dat`; only `--angou` may be combined with it. |

`--readall`, `--apply`, `--read-flags`, and `--word` are separate operations; do not combine them with each other or comparison modifiers. `--word` accepts `--angou`. Structural comparison of `.gan`, `.cgm`, or `.tcr` fails if either input cannot be parsed completely.

PCK reports include an `ID` column when embedded `.ss` sources contain `SCENE_SCRIPT_ID` metadata. Comparison includes these IDs.

#### Decryption Keys

Place `--angou VALUE` at the end of the arguments before any `--` separator. Supply `VALUE` as a separate, nonempty argument.

| Value | Meaning |
|---|---|
| File path | Read a key from `暗号.dat`, `key.txt`, `Scene.pck`, or `SiglusEngine*.exe`. |
| Directory path | Search that directory's immediate files. |
| `angou=text` | Derive a key from a literal `暗号.dat` first line. |
| `key=bytes` | Supply a 16-byte key. Prefer explicit `0xNN` tokens to avoid numeric ambiguity. |

Key lookup tries the explicit source, the input PCK's embedded keys, the input directory, then its parent. An explicit file or directory that yields a key skips the parent lookup. Directory order is `Scene.pck`, `Scene*.pck`, `暗号.dat`, `key.txt`, then `SiglusEngine*.exe`. Lookup scans immediate files. During PCK extraction and DAT directory disassembly, `-x` warns and skips invalid explicit key sources and unreadable key directories. Other commands require an explicit source to yield a key. When a candidate fails decryption, lookup can try subsequent candidates.

Encrypted `Gameexe.dat` requires a configuration assignment on each nonblank line after comment removal. For example, `#WINDOW_XSIZE=640`. The `#` is optional. Names begin with an ASCII letter, digit, or underscore and may also contain periods, brackets, hyphens, spaces, and tabs. Values may contain Unicode. Decryption fails if keys produce different valid texts.

Text keys from `暗号.dat` and `angou=text` can differ from official Windows conversion. For existing official files, prefer the matching engine executable or its raw key. Embedded `暗号.dat` supports UTF-16 or UTF-32 with a BOM. A 16-byte `key.txt` is read as binary; other text keys are parsed as `0xNN`, two-digit hex, then decimal, taking the first 16 matches from the first applicable format. Thus sixteen `10` tokens mean hex `0x10` bytes.

```bash
siglus-ssu -x /path/to/Scene.pck --angou /path/to/SiglusEngine.exe
siglus-ssu -a --angou "angou=literal_angou_string"
siglus-ssu -a --angou "key=0xA9,0x86,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00"
```

#### Read-Flag JSON

A zero flag means not marked as read, which may differ from whether the content has appeared. Flag indices start at `0` per scene.

The report contains `savePath`, `pckPath` (`null` without a PCK), `summary`, and `scenes`. The summary gives scene and flag counts, read/unread counts, and status counts. Each scene includes its name, status, saved and PCK flag counts, read/unread counts, and `unreadFlags`. Each unread entry has `index` and `line`. A matched `line` is a one-based original source line, not a decompiled-source location; unavailable values are `null`.

| Scene `status` | Meaning |
|---|---|
| `notChecked` | No PCK supplied; saved indices are unvalidated. |
| `matched` | Scene name and flag count match. |
| `ignored` | Saved scene is absent from the PCK and ignored by the engine. |
| `countMismatch` | Flag count differs; the engine ignores these saved flags. |
| `sceneUnavailable` | PCK scene or flag table could not be decoded. |

The report includes saved records only; PCK scenes without a saved record start unread in-game. All saved counts and indices are retained, including ignored or mismatched records. `countMismatch` or `sceneUnavailable` returns `1` after writing the report; `ignored` does not cause failure.

#### Payload Comparison Results

Payload comparison covers bytecode, labels, properties, strings (including unused strings), read flags, and package command/property routing. It ignores string storage order, unused trailing zero Z-label entries, and debug-only name data. Identifier names remain significant.

| `.pck` scene `PAYLOAD` | `.dat` result | Meaning |
|---|---|---|
| `same` | `identical` | Normalized payloads match. |
| `text_only` | `text_only` | Structure matches but strings differ. Resource or scene names may also differ, affecting behavior. |
| `real_diff` | `real_diff` | Other payload data differs. |
| `-` | `unavailable` | A scene is missing or cannot be decoded. |
| `INCOMPLETE` | `INCOMPLETE` | Disassembly or validation is incomplete, even if input bytes match. |

Whole-PCK equality requires no added or missing scenes and no `text_only`, `real_diff`, unavailable, or `INCOMPLETE` results. Header and embedded-source differences are reported separately. Validated identical scenes are omitted from the differences table; its payload summary counts listed scenes only.

Exit status `0` alone does not establish equality: differences are reported as results. `INCOMPLETE` returns `1`.

#### Examples

Analyze and compare files:

```bash
siglus-ssu -a /path/to/Scene.pck
siglus-ssu -a --payload /path/to/original.pck /path/to/rebuilt.pck
siglus-ssu -a --disam /path/to/chapter1.dat
```

Export unread flags or mark all scenes read:

```bash
siglus-ssu -a --read-flags /path/to/savedata/read.sav /path/to/Scene.pck
siglus-ssu -a --readall /path/to/savedata/read.sav
```

Analyze `global.sav` to generate `global.txt`, edit supported values, then apply them. Analysis preserves an existing `global.txt`.

```bash
siglus-ssu -a /path/to/savedata/global.sav
siglus-ssu -a --apply /path/to/savedata/global.sav
```

#### Word Count Output (`-a --word`)

```bash
siglus-ssu -a --word /path/to/Scene.pck /path/to/counts.csv
```

Counts are dialogue units, not a universal linguistic word count:

- Han, Hiragana, Katakana, and Bopomofo count per character. A halfwidth Katakana base plus voiced/semi-voiced mark counts as one.
- Hangul, other letters, and numbers count by contiguous word run.
- Internal apostrophes, hyphens, and underscores join word runs. Internal `.`, `,`, `/`, `:`, and fullwidth equivalents join numeric runs when surrounded by decimal digits.
- Punctuation, whitespace, emoji, and other symbols add no units.

The counter evaluates `print` text built from string literals by concatenation or repetition. Repeat counts can use integer literals, unary signs, and integer addition, subtraction, and multiplication.

| CSV column | Meaning |
|---|---|
| `type` | `dat` or `ss`. |
| `path` | Relative path inside the PCK. |
| `status` | `ok`, `failed`, or `unavailable`. |
| `dialogue_lines` | Number of dialogue entries. |
| `dialogue_count` | Total dialogue units. |
| `error` | Failure reason, if any. |

Failed or unavailable rows have empty counts; totals include successful rows only. Partial results are written before exit status `1`. A missing or unreadable declared source section produces `ss_status=unavailable` and source totals `N/A`; a PCK without embedded sources produces only DAT rows, `ss_status=not_embedded`, and succeeds if all DAT files were counted. Source counting stops at DOS EOF as in compilation.

---

### `-d` / `--db` — Export and Compile `.dbs` Databases

Exports game databases to CSV and compiles edited CSV files back to `.dbs`.

#### Syntax

```
siglus-ssu -d --x <input_dir | input_file.dbs> <output_dir>
siglus-ssu -d --a <input_file.dbs> [input_file_2.dbs]
siglus-ssu -d --c [--type N] [--set-shuffle SEED] <input_csv | input_dir> <output_dbs | output_dir>
siglus-ssu -d --c [--type N] [--set-shuffle SEED] --test-shuffle [skip0] <expected.dbs> <input_csv> <output_dbs | output_dir>
```

| Parameter | Description |
|---|---|
| `--x` | Export `.dbs` to CSV, preserving existing CSV files. |
| `--a` | Analyze one database or compare two. |
| `--c` | Compile CSV to `.dbs`. |
| `--type N` | Output database type (`0`–`2147483647`). Normal creation defaults to `1`. With `--test-shuffle`, the default comes from the reference DBS. Type `0` uses CP932 strings. Other types use UTF-16LE. |
| `--set-shuffle SEED` | Set the random-padding seed (decimal or hexadecimal; default `1`). |
| `--test-shuffle [skip0]` | Try up to 16,777,216 random-generator skip counts from `skip0` (default `0`) to match a reference database's padding. Writes output only after an exact match and preserves the reference file. Single-file mode only. |

Directory export and compilation scan recursively and preserve subdirectories. Batch compilation rejects output-name collisions such as `name.csv` and `name.dbs.csv`, including case-only collisions.

Comparison uses decoded string values. It checks up to 2,000,000 cells and prints at most 20 differences, reporting when a limit is reached.

#### Examples

```bash
siglus-ssu -d --x /path/to/dbs_dir/ /path/to/csv_out/
siglus-ssu -d --c /path/to/gamedb.dbs.csv /path/to/translated.dbs
siglus-ssu -d --a /path/to/original.dbs /path/to/translated.dbs
```

#### CSV Format

CSV files use UTF-8 with BOM and CRLF, suitable for Excel. Keep the first two rows and the first column:

- `#DATANO`: column call numbers, after the first cell containing `#DATANO`.
- `#DATATYPE`: corresponding types, commonly `S` (string) and `V` (numeric/32-bit value).
- Data rows: the first cell is the row call number, followed by values in header order.

Row and column call numbers must fit signed 32-bit integers.

Use normal CSV quoting: double embedded quotes, keep backslashes literal, and place actual newlines or tabs inside quoted fields. Malformed quoting, extra fields, and unencodable strings fail compilation with the CSV location.

---

### `-k` / `--koe` — Collect Voice Files by Character

Matches scene voice references to `.ovk` entries, extracts `.ogg` files by character, and writes `koe_master.csv` with dialogue and call locations.

#### Syntax

```
siglus-ssu -k [--stats-only] <scene_input> <voice_dir> <output_dir> [--angou VALUE]
siglus-ssu -k [--stats-only] --single KOE_NO <voice_dir> <output_dir>
```

| Parameter | Description |
|---|---|
| `<scene_input>` | `Scene.pck`, a scene `.dat`, or a recursively scanned DAT directory. Not used with `--single`. |
| `<voice_dir>` | One `zNNNN.ovk` archive, or a directory scanned for those archives at the immediate level. `NNNN` is the four-digit scene number. |
| `<output_dir>` | Destination for audio and, in normal mode, `koe_master.csv`. |
| `--angou VALUE` | [Decryption key source](#decryption-keys) for encrypted scene input. Not valid with `--single`. |
| `--stats-only` | Write the CSV and summary without audio. With `--single`, write only the summary. |
| `--single KOE_NO` | Extract one global voice number as `KOE(XXXXXXXXX).ogg` directly in the output directory, without CSV or character subdirectories. A missing entry returns `1`. |

#### Output Structure

```
<output_dir>/
  koe_master.csv
  <character name or %EMPTY>/KOE(000000001).ogg
  unreferenced/KOE(000000002).ogg
```

`%EMPTY` means no character name was found. Unsafe directory-name characters are percent-escaped; CSV names retain their original text. Case-only differences follow the output filesystem's rules.

Scene scan or OVK index errors stop the command before it writes the CSV or audio. The CSV cannot replace a file read for its key. Unreferenced archive entries go to `unreferenced/`. The summary's voice duration includes referenced entries only. Unreadable durations are counted under `Duration failed` without preventing CSV output.

#### `koe_master.csv` Format (Normal Mode Only)

| Column | Description |
|---|---|
| `koe_no` | Global voice number, `scene_no × 100000 + entry_no`. |
| `character` | Character name inferred from the scene. |
| `text` | Associated dialogue. |
| `duration_sec` | Duration in seconds; empty when unavailable. |
| `callsite` | Semicolon-separated `filename:line` locations, or `Scene.pck!scene.dat:line` for PCK input. |

Distinct character/text pairs retain separate rows for the same voice number. Repeated references to the same pair share a row. Conditional alternative names are retained when identifiable; each audio file uses one inferred directory name.

#### Examples

```bash
siglus-ssu -k /path/to/Scene.pck /path/to/voice/ /path/to/voice_out/
siglus-ssu -k --stats-only /path/to/scene_dir/ /path/to/voice/ /path/to/voice_out/
siglus-ssu -k --single 123456789 /path/to/voice/ /path/to/voice_out/
```

---

### `-e` / `--exec` / `--execute` — Execute at a Script Label

Launches `SiglusEngine.exe` at a scene's `#z` label. Requires a compatible Windows execution environment; this command does not configure or invoke Wine.

```
siglus-ssu -e <path_to_engine> <scene_name> <label>
```

| Parameter | Description |
|---|---|
| `<path_to_engine>` | Path to `SiglusEngine.exe`. |
| `<scene_name>` | Nonempty bare scene name, optionally ending in `.ss`; no directory components or whitespace-only names. |
| `<label>` | Non-negative decimal label number. Optional prefixes are `#`, `z`, and `#z`. |

The command creates or reuses `work_YYYYMMDD` beside the executable, launches the engine, and returns immediately. The work directory is retained.

```bash
siglus-ssu -e /path/to/SiglusEngine.exe chapter2 5
siglus-ssu -e /path/to/SiglusEngine.exe chapter2.ss "#z5"
```

---

### `-m` / `--textmap` — Text Mapping for Translation

Exports scene `.dat` strings to CSV and applies translations in-place. Source `.ss` editing is not supported.

```
siglus-ssu -m <path_to_dat | path_to_dir> [--angou VALUE]
siglus-ssu -m --apply <path_to_dat | path_to_dir> [--angou VALUE]
```

Directory inputs are scanned recursively. Configuration and key files are skipped. For encrypted files, the command first tries [decryption keys](#decryption-keys) found for the selected directory. If those fail on a nested DAT, it also looks for keys starting in that DAT’s directory.

#### Workflow

1. Export `chapter1.dat.csv` beside the DAT. Re-exporting preserves an existing CSV:

   ```bash
   siglus-ssu -m /path/to/chapter1.dat
   ```

2. Edit the CSV's `replacement` column, leaving `index` and `original` unchanged.
3. Apply translations:

   ```bash
   siglus-ssu -m --apply /path/to/chapter1.dat
   ```

The command rewrites the DAT, preserving its encryption and compression. Back up the original before applying translations.

The CSV must include `index`, `original`, and `replacement`. Invalid or duplicate indices and mismatched originals leave that DAT unchanged and return `1`. Already-applied rows are accepted. Directory processing continues after failures and returns `1` if any file failed.

#### `.dat.csv` Format

| Column | Description |
|---|---|
| `index` | String-table index. |
| `kind` | `1` = dialogue, `2` = speaker name, `3` = other text. |
| `original` | Original string, escaped as below. |
| `replacement` | Replacement, initially equal to `original`. |

Use `\\`, `\n`, `\r`, and `\t` for backslash, newline, carriage return, and tab. Isolated UTF-16 surrogate units use `\uD800`–`\uDFFF` escapes.

---

### `-g` / `--g00` — Work with `.g00` Image Files

Analyzes, extracts, merges, creates, and updates SiglusEngine images.

| Type | Contents |
|---|---|
| type0 | Opaque image, decoded as 32-bit BGRA. |
| type1 | Paletted image, up to 256 colors. |
| type2 | Multiple image cuts with placement information. |
| type3 | JPEG image. |

Image processing requires [Pillow](https://pillow.readthedocs.io/) (`pip install pillow`). Analysis and untrimmed type3 JPEG extraction can run without it. Untrimmed extraction checks the primary JPEG's markers and writes the original JPEG bytes.

#### Syntax

```
siglus-ssu -g --a <input_g00>
siglus-ssu -g --x [--trim] <input_g00 | input_dir> <output_dir>
siglus-ssu -g --m [--trim] <input_g00[:cutNNN]> <input_g00[:cutNNN]> [...] [--o <output_dir>]
siglus-ssu -g --c [--type N] [--refer <ref_g00 | ref_dir>] <input_png | input_jpeg | input_layout | input_dir> [output_g00 | output_dir]
```

| Parameter | Description |
|---|---|
| `--a` | Show image type, dimensions, and cut information. |
| `--x` | Extract PNG/JPEG files and, for untrimmed type2, a rebuildable `.type2.json` layout. Existing image and JSON targets are skipped. |
| `--trim` | Crop transparent edges, or top-left background color for opaque images. Available with `--x` and `--m`; trimmed type2 extraction does not create a JSON layout. |
| `--m` | Composite images or cuts into one PNG, aligning type2 cuts by their centers. |
| `--c` | Create a new G00, or update from `--refer`. |
| `--o`, `-o`, `--output`, `--output-dir` | Merge output directory; default is the current directory. |
| `--type N`, `--t N` | Choose the created type, or validate the reference type during updates. Only valid with `--c`. |
| `--refer <ref_g00 \| ref_dir>` | Update from a reference. Directory input requires a reference directory. Single-file input accepts a reference file or directory. File lookup in the reference directory warns on case ambiguity. Omitting the output path updates the reference in place. |
| `:cutNNN` | Select a type2 cut for merging, for example `sprite.g00:cut002`. |

Extraction and creation scan directory inputs at the immediate level only. When creating a new type2 layout, extraction fails if an existing cut PNG is unreadable or has a different size from the untrimmed cut.

#### Create and Update

For creation, PNG defaults to type0 and JPEG to type3. Type0 output sets alpha to 255. Use `--type 2` to create from an image or a `.json`/`.jsonc` layout. A single image uses a matching sidecar such as `sprite.type2.json` if found and creates one cut otherwise. For directory input, `--type 2` processes layouts if present and images otherwise. Creation supports types 0, 2, and 3.

Creation without an output path writes beside the input. Output paths must be distinct and must avoid source images, layouts, and other targets' references. In-place updates verify the reference bytes before replacement. If interrupted, remove `.siglus-g00.lockdir` after confirming no update is running.

Use JSON/JSONC layouts in create mode. Name individual replacements `<basename>_cut###.png` when a reference has multiple cuts.

```bash
siglus-ssu -g --x /path/to/sprite.g00 /path/to/work/
siglus-ssu -g --m /path/to/sprite.g00:cut005 /path/to/overlay.g00 --o /path/to/out/
siglus-ssu -g --c /path/to/new_bg.png /path/to/game_bg.g00
siglus-ssu -g --c /path/to/new_bg.png /path/to/game_bg.g00 --refer /path/to/original_bg.g00
```

#### Type2 JSON Layout

Untrimmed type2 extraction produces `<basename>.type2.json` and either `<basename>.png` for one cut or `<basename>_cut000.png`, `<basename>_cut001.png`, etc. for multiple cuts. Edit the PNGs, then rebuild from the JSON:

```bash
siglus-ssu -g --c --type 2 /path/to/work/sprite.type2.json /path/to/rebuilt/sprite.g00
```

Use the layout to rebuild all cuts. Extraction preserves RGB beneath transparent pixels, and rebuilding uses the edited PNG values.

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

- `canvas` sets the output canvas dimensions.
- `cuts` assigns successive indices. A cut can set an explicit `index`. `null` leaves an empty slot.
- `source` paths can be relative to the layout. Both `/` and `\` are accepted. A cut without `source` uses `default_source` or the companion image when one was supplied.
- `canvas_rect` sets placement. Optional `source_rect` selects part of the PNG; otherwise the whole PNG is used. Source and canvas rectangles must have equal dimensions.
- Per-cut `center` defaults to `default_center`, or `(0, 0)` if absent.

---

### `-s` / `--sound` — Work with Audio Files

| Format | Extraction output |
|---|---|
| `.nwa` | `.wav` |
| `.owp` | `.ogg` |
| `.ovk` | Numbered `.ogg` voice entries |

#### Syntax

```
siglus-ssu -s --x <input_dir | input_file> <output_dir> [--trim <Gameexe.dat | Gameexe.ini>] [--angou VALUE]
siglus-ssu -s --a <input_file.(nwa | ovk | owp)> [input_file_2.ovk]
siglus-ssu -s --c <input_ogg | input_dir> <output_dir>
siglus-ssu -s --play <input_file.(nwa | owp | ogg) | input_dir> [Gameexe.dat | Gameexe.ini] [--angou VALUE]
```

| Parameter | Description |
|---|---|
| `--x` | Extract audio. Directory inputs are recursive and preserve subdirectories. Existing outputs are overwritten unless they collide with another output or a file read for this operation. |
| `--a` | Analyze one audio file, or compare entries in two OVK archives. |
| `--c` | Create OWP or OVK from Ogg files using the naming rules below. Directory inputs are recursive and preserve subdirectories. |
| `--play` | Preview BGM with Gameexe loop points in a terminal player. Requires `ffplay` on `PATH` and `psutil` (`pip install psutil`). Supports NWA/OWP/Ogg, not OVK. |
| `--trim <Gameexe.dat \| Gameexe.ini>` | Extract only the `repeat`–`end` loop region of matching NWA/OWP tracks. OWP trimming requires `ffmpeg`; NWA trimming does not. OVK is unaffected. |
| `--angou VALUE` | [Key source](#decryption-keys) for encrypted Gameexe data used by trimming or playback. Ignored by other sound operations. |

Trimming fails if decoding fails or the selected loop region contains no audio samples. NWA extraction fails if a compressed block is incomplete. The tool preserves any existing output for the track in these cases.

#### OVK Naming

Extraction writes `<basename>.ogg` for one entry, or `<basename>_<entry_no>.ogg` for multiple entries. Creating or extracting OWP and OVK requires complete Ogg streams. OVK extraction reads all entries before publishing files. A changed index stops publication for that archive. The tool rolls back the archive's outputs if publishing fails.

Creation groups at least two `<basename>_<N>.ogg` files into `<basename>.ovk`. Other files, including a lone numbered file, become individual OWP files. OVK creation and loop playback require a constant sample rate across the links of chained Ogg audio. Loop playback also requires the same codec and channel count across links, and the same bit depth for FLAC. For Vorbis, Opus, Speex, and FLAC, sample counts start at each link's audio origin.

#### Loop Playback

The player matches audio basenames to `#BGM.*` entries. With no Gameexe path, it checks the audio directory's parent for `Gameexe.dat`, then nearby `Gameexe.*` files, preferring INI among the fallback files. For duplicate entries referencing one file, it prefers the matching BGM name, then the first entry.

Playback starts at `start` and loops over `repeat`–`end`. `end=-1` or an end beyond the audio length means EOF. Directory input recursively collects matching tracks; unmatched files are skipped with a diagnostic.

| Command | Action |
|---|---|
| `p`, `q`, `h` | Pause/resume, quit, help. |
| `b`, `n` | Previous/next playlist track. |
| `play N` | Play playlist track `N` (1-based). |
| `l` | Recenter the playlist on the current track. |
| `u`, `d` | Scroll the playlist by one page. |
| `gg`, `G` | Scroll to the first/last playlist page. |

Commands must be ASCII; `N` must use digits `0`–`9` and be positive. Track names and paths may contain Unicode.

#### Examples

Extract, trim, or create audio:

```bash
siglus-ssu -s --x /path/to/voice/z0001.ovk /path/to/ogg_out/
siglus-ssu -s --x /path/to/bgm/ /path/to/trimmed/ --trim /path/to/Gameexe.dat
siglus-ssu -s --c /path/to/translated_ogg/ /path/to/audio_out/
```

Compare voice archives or preview a BGM playlist:

```bash
siglus-ssu -s --a /path/to/old/z0001.ovk /path/to/new/z0001.ovk
siglus-ssu -s --play /path/to/BGM/
```

---

### `-v` / `--video` — Work with `.omv` Video Files

Extraction copies embedded Ogg streams, including audio. Creation wraps only the first Theora stream, without re-encoding. Both reject missing, truncated, or checksum-invalid Ogg pages.

#### Syntax

```
siglus-ssu -v --x <input_dir | input_file.omv> <output_dir>
siglus-ssu -v --a <input_file.omv>
siglus-ssu -v --c <input_ogv> <output_omv | output_dir> [--refer ref.omv] [--mode N] [--flags N]
```

| Parameter | Description |
|---|---|
| `--x` | Extract `.ogv`. Directory inputs are recursive and preserve subdirectories. |
| `--a` | Show header, frame, and available Theora stream information. |
| `--c` | Wrap a Theora stream whose encoded planes already match the selected mode. |
| `--refer <ref.omv>` | Copy mode and per-frame flags from a reference; explicit `--mode` and `--flags` override them. No video data is copied. |
| `--mode N` | Set pixel interpretation mode without converting pixels. Accepts decimal or hexadecimal; default `2` without a reference. |
| `--flags N` | Set raw per-frame flags; normally leave at `0`. Use original bit positions such as `0x1A2B3C00`, or ranges such as `0-9:0x1A2B3C00,10-:0x00000000`. Low 8 bits are generated automatically. |

Creation treats its output as a directory if it exists as one, ends in a separator, or has no extension. Use a `.omv` extension for an explicit output file.

Existing outputs require `y` or `yes` at `Overwrite? [y/N]`. The command preserves the file and reports failure if you decline or another process fills a previously unused target during conversion. OMV creation also fails if the selected Theora data changes after indexing. Batch extraction continues with other files.

#### Pixel Layouts and `.ogv` Inputs

Use `-v --a` to record the original OMV mode. The extracted Ogg omits it. For the layouts below, prepare full-size Theora 4:4:4 planes.

| Mode | Layout |
|---|---|
| `0` | B, G, R planes; opaque. |
| `1` | B, G, R planes, each followed by an alpha segment. |
| `2` | Full-range BT.601 Y, U, V. |

For mode `1`, visible height `H` needs Theora picture height `H + ceil(H / 3)`. The first `H` rows of each plane hold color. Concatenate the following alpha segments in plane order and take the first `H` rows as alpha. A 1080-row image needs a 1440-row encoded picture.

Ordinary players interpret these planes as YUV. Modes `0` and `1` require color or alpha reconstruction for normal viewing. `--mode` and `--refer` set pixel interpretation metadata, so supply an Ogg encoded for the target layout.

For ordinary opaque SDR video, prepare mode `2` using FFmpeg with `libtheora`:

```bash
ffmpeg -i input_video -map 0:v:0 -an -vf "scale=out_range=full:out_color_matrix=bt601,format=yuv444p" -c:v libtheora -q:v 8 -color_range pc output.ogv
siglus-ssu -v --c output.ogv output.omv --mode 2
```

Correct missing or inaccurate input color metadata using the scale filter's `in_range` / `in_color_matrix` options. This example preserves neither audio nor transparency.

#### Examples

```bash
siglus-ssu -v --x /path/to/movie/ /path/to/ogv_out/
siglus-ssu -v --a /path/to/op.omv
siglus-ssu -v --c /path/to/translated.ogv /path/to/translated.omv --refer /path/to/original.omv
```

---

### `-p` / `--patch` — Patch `SiglusEngine.exe`

Changes engine keys, language settings, or region detection. By default, writes a new executable; `--inplace` overwrites the original.

#### Syntax

```bash
siglus-ssu -p --altkey <input_exe> <input_key> [-o output_exe] [--inplace]
siglus-ssu -p --lang (cjk | cjk-path | config.json) <input_exe> [-o output_exe] [--inplace] [--allow-partial] [--revert]
siglus-ssu -p --info <input_exe>
siglus-ssu -p --loc (0 | 1) <input_exe> [-o output_exe] [--inplace]
```

| Parameter | Description |
|---|---|
| `<input_exe>` | Engine executable. Symbolic-link input and output paths are rejected. |
| `<input_key>` | For `--altkey`: a `key.txt`, `暗号.dat`, `SiglusEngine*.exe`, or `Scene.pck` file, or a `key=bytes` / `angou=text` literal. Directories are not accepted. The key file cannot also be the output. |
| `-o`, `--output` | Choose the output executable. Defaults use `_alt.exe`, `_CJK.exe`, `_CJKPATH.exe`, `_LOC0.exe`, or `_LOC1.exe`; JSON uses `_<CONFIG>.exe` and reverting uses `_ORIGINAL.exe`. |
| `--inplace` | Overwrite the input; cannot be combined with `-o`. |
| `--lang cjk` | Set CJK font charset, locale `chinese`, and language code `zh`, keeping game file/save paths unchanged. |
| `--lang cjk-path` | Apply `cjk` and use `GameexeZH.dat`, `SceneZH.pck`, and `savedata_zh`. |
| `--lang config.json` | Apply all six fields from a JSON file or one quoted inline JSON object. The output cannot overwrite the configuration file. |
| `--allow-partial` | Apply supported parts of a language preset even if some components are unavailable. Otherwise all components are required before any output is written. |
| `--revert` | Restore the byte-identical original from a previous language patch. Requires `--lang`; cannot be combined with `--allow-partial`. |
| `--info` | Inspect patchable key, language, and region settings without writing. |
| `--loc 0` | Disable region detection. |
| `--loc 1` | Restore region detection for an EXE patched by this tool's `--loc 0`. |

#### Language Configuration

JSON requires all six fields:

```json
{
  "pck": "SceneZH.pck",
  "gameexe": "GameexeZH.dat",
  "save": "savedata_zh",
  "charset": 134,
  "locale": "chinese",
  "language_code": "zh"
}
```

An already language-patched engine can be patched directly to another configuration. For `charset`, common values are `0` (ANSI), `128` (Shift-JIS), and `134` (GB2312). CJK presets use `134` for recognized Japanese/CJK font slots; unsupported builds fail unless `--allow-partial` is selected.

#### Examples

```bash
siglus-ssu -p --info /path/to/SiglusEngine.exe
siglus-ssu -p --altkey /path/to/SiglusEngine.exe /path/to/key.txt -o /path/to/patched.exe
siglus-ssu -p --lang cjk-path /path/to/SiglusEngine.exe
siglus-ssu -p --lang config.json /path/to/SiglusEngine.exe
siglus-ssu -p --lang config.json --revert /path/to/SiglusEngine_CONFIG.exe
siglus-ssu -p --loc 0 /path/to/SiglusEngine.exe
```

---

### `test` — Round-Trip Compile Test

Extracts and rebuilds one PCK or all immediate `.pck` files in a directory, then checks byte identity or normalized payload equality. Directory inputs are processed sequentially, continuing after failures. Temporary files are removed afterward.

By default, the command uses embedded original sources. PCKs with no declared source section are skipped; a declared but unreadable or empty source section fails.

#### Syntax

```bash
siglus-ssu [--const-profile N] test [--serial] [--report-json FILE] <input_pck|input_dir>
siglus-ssu --const-profile N test --allow-invalid [--serial] [--report-json FILE] <input_pck|input_dir>
siglus-ssu --const-profile N test --decompile [--serial] [--report-json FILE] <input_pck|input_dir>
```

| Option | Description |
|---|---|
| `--decompile` | Reconstruct source without using embedded sources, rebuild it, and compare payloads. Requires an explicit global profile; uses strict UTF-8 without retries. |
| `--allow-invalid` | With an explicit profile in embedded-source mode, compile as UTF-8 with replacement for invalid bytes. Not accepted with `--decompile`. |
| `--serial` | Disable parallel compilation during rebuilds. |
| `--report-json FILE` | Write results and timings as JSON. Also accepts `--report-json=FILE`. The report cannot replace an input PCK or a file read for its key. |

An explicit `--const-profile` makes one attempt with that profile and normal encoding detection, unless `--allow-invalid` is supplied. Without an explicit profile, embedded-source tests try profiles `0`–`10`, then retry with UTF-8 replacement if needed. An explicit string multiplier applies to all attempts.

#### Results

| Status | Meaning |
|---|---|
| `EXACT` | Rebuilt PCK is byte-identical. |
| `PAYLOAD_SAME` | Normalized payloads match. Decompile-mode success always uses this status. |
| `FAIL` | Rebuild failed or payloads differ, including `text_only` or incomplete results. |
| `SKIP` | No embedded sources declared in embedded-source mode. |

The command exits with `0` if at least one file passes and none fail; any failure or an all-skipped run returns `1`. The summary includes timings and failed files.

JSON contains a `decompile` flag and `results`. Each result has `path`, `status`, `detail`, `elapsed`, `timings`, `profile`, `allow_invalid`, and `compile_backend` (`rust` or `python`). The last three fields are `null` for failed or skipped files.

```bash
siglus-ssu test /path/to/Scene.pck
siglus-ssu test --report-json /path/to/results.json /path/to/pck_dir/
siglus-ssu --const-profile 2 test --allow-invalid /path/to/Scene.pck
siglus-ssu --const-profile 0 test --decompile /path/to/Scene.pck
```

<a id="siglusss-language-spec"></a>

## SiglusSS Language Specification

The selected [const profile](#const-profiles) supplies the forms, built-in members, and command signatures used by both compiler backends. See the profile tables in [const.py](src/siglus_ssu/const.py) for these definitions.

### Source and preprocessing

A scene is a `.ss` file. Global `.inc` files come from the same directory, in filename order after ASCII lowercasing. The compiler detects the encoding per file unless given `--charset`, removes leading BOM characters, normalizes CRLF and CR to LF, and stops at the first DOS EOF character (U+001A). Use `--allow-invalid` to replace undecodable bytes.

The compiler loads global declarations before processing each scene.

1. Strip comments and lowercase ASCII outside quotes.
2. Resolve conditional directives and collect the local declarations between `#inc_start` and `#inc_end`.
3. Process those declarations and expand replacements in the remaining scene text.
4. Tokenize, parse, check forms, and emit bytecode. Link global user commands across the directory.

`;` and `//` start line comments. `/* ... */` removes a non-nesting block and preserves line breaks. Adjacent text can join across a block comment. `/*/` also closes an empty block comment. Quoted literals protect comment markers. An unclosed block comment is an error.

A first line beginning with `// #SCENE_SCRIPT_ID = ` followed immediately by four ASCII digits supplies the scene ID. The compiler reads the first four digits and ignores the rest of that line.

#### Conditional directives and scene-local declarations

```text
#ifdef name
#elseifdef name
#else
#endif
```

`#ifdef` and `#elseifdef` test whether an include name has been registered. A tested name starts with an ASCII letter, a CP932 double-byte character, `_`, or `@`. Subsequent characters can also be ASCII digits. Nesting is limited to 15 levels. Only the innermost condition governs whether text is included. An inner true branch can include text inside an outer false branch.

In `.ss`, conditions have access to global include names. The compiler checks them before registering scene-local names. In a `.inc` file, conditional directives occur in declaration text, where conditions can use the names already registered when that text is collected.

`#inc_start` switches to collecting local declarations, and `#inc_end` switches back to scene text. A repeated start inside an open region leaves collection active. One end closes the region. An end outside a region or an open region at EOF is an error.

### Tokens

Spaces, tabs, and newlines separate tokens. Statements can span lines or share a line. In the grammar, braces mean repetition, brackets mark optional parts, and quotes mark literal tokens. `ascii-letter` denotes `a`–`z` after case folding, `digit` denotes `0`–`9`, and `hex-digit` also includes `a`–`f`.

```text
identifier ::= id-start { id-start | digit }
id-start   ::= "_" | "$" | "@" | ascii-letter
label      ::= "#" { "_" | ascii-letter | digit }
decimal    ::= digit { digit }
integer    ::= decimal | "0b" { "0" | "1" } | "0x" { hex-digit }
```

Reserved words

```text
command  property  goto  gosub  gosubstr  return
if  elseif  else  for  while  continue  break  switch  case  default
```

The lexer recognizes `#z` followed by one to three digits as a z-label when the number is below `100` in profiles `7` and `8`, or below `1000` in other profiles. All other matches of `label` are ordinary labels, including `#` and `#z1234`. Z-label definitions reserve a numeric slot, so `#z1` and `#z01` cannot both be defined. References use the full spelling after ASCII case folding. Each scene needs a definition for numeric slot `0`. All labels are unique within a scene, and all references must resolve within that scene.

Integer literals wrap to signed 32-bit values. A sign is a unary operator. Bare `0b` and `0x` denote zero. A single-quoted literal encloses one character after escape processing and yields its code as `int`. A double-quoted literal has form `str`. Literals written in `.ss` must fit on one physical line.

| Escape | Single quotes | Double quotes |
| --- | --- | --- |
| `\\` | Backslash | Backslash |
| `\n` | The character `n` | LF |
| `\'` | Apostrophe | — |
| `\"` | — | Double quote |

Runs of characters that encode to two bytes in Windows CP932 form bare string tokens. The brackets `【` and `】` are delimiters. Use double quotes for text outside that set or to keep spaces and punctuation in one string token.

### Include declarations

Global `.inc` files and scene-local include regions use the same declaration grammar.

```text
inc-file ::= { declaration }
declaration ::= ("#replace" | "#define" | "#define_s") name text
              | "#macro" macro-name ["(" parameter {"," parameter} ")"] text
              | "#property" name [":" form-name ["[" decimal "]"]]
              | "#command" name ["(" inc-arg {"," inc-arg} ")"] [":" form-name]
              | "#expand" text

parameter ::= parameter-name ["(" default-text ")"]
inc-arg   ::= form-name ["(" default-literal ")"]
```

| Declaration | Where the name ends |
| --- | --- |
| `#replace`, `#define` | Space, tab, or newline |
| `#define_s` | Tab or newline, so the name can contain spaces |
| `#macro` | Space, tab, newline, or `(`. The name starts with `@`. |
| `#property` | Space, tab, newline, or `:` |
| `#command` | Space, tab, newline, `(`, or `:` |

Include names share a namespace with the global include declarations visible to the scene. The compiler rejects duplicate names. A declaration name used directly as a scene identifier must also follow the scene identifier grammar.

#### Text replacement and macros

Declaration text skips leading whitespace, ends at the next unescaped `#` in included text or EOF, joins lines with spaces, and trims trailing spaces and tabs. Write `##` to emit a literal `#`, including within a quoted string in declaration text.

`#replace` inserts text and advances past it. `#define` and `#define_s` rescan inserted text. Matches operate on characters before tokenization, including inside quotes. Each replacement table prefers its longest matching name. When a definition and a macro parameter both match, the lexicographically larger name wins. A parameter wins a tie.

Write macro arguments immediately after the name in parentheses. The name alone and `()` both supply zero arguments. Omitted trailing arguments use nonempty defaults. Commas outside quotes and nested parentheses separate arguments. Empty entries and excess arguments are errors. Omit the parameter list when declaring a zero-parameter macro. A parameter default ends at the first `)` and cannot contain a tab or newline.

The compiler expands arguments and defaults before substituting them, then expands the body with the resulting parameter values. A repeated parameter name uses its first value. The other occurrences still take arguments or defaults. After expanding the body, scanning resumes after the inserted text.

`#expand` expands its text immediately and reads the result as more include declarations. Replacements and macros become available as they are collected. The compiler queues `#property` and `#command` text, expands it after collection, and registers properties before commands within each include. All global includes finish collection before this registration pass.

Macro nesting is limited to 128. Text expansion stops after more than 10,000 consecutive scanning steps without reaching a new minimum remaining length. The same guard counts declarations during `#expand` processing.

#### Property and command signatures

- `#property` defaults to `int` and rejects `void`. Only `intlist` and `strlist` take a bracketed size. The size is an unsigned decimal spelling.
- `#command` defaults to return form `int`. Write only forms in its parameter list. Omit the parentheses for zero parameters.
- An `int` default uses signed decimal notation, with an optional `+` or `-` directly before the digits. A `str` default uses a double-quoted literal. Starting with the first default, all parameters must have defaults. The compiler fills omitted `int` arguments. Pass `str` arguments explicitly even when the declaration supplies a default.

### Scene grammar

```text
scene         ::= { statement }
statement     ::= label-target | command-def | property-def | jump | return-stmt
                | if-stmt | for-stmt | while-stmt | "continue" | "break"
                | switch-stmt | element-expr [assign-op expr]
                | "【" string-token "】" | string-token

command-def   ::= "command" identifier [ "(" [property-def {"," property-def}] ")" ]
                  [":" form] block
property-def  ::= "property" identifier [":" form]
form          ::= form-name ["[" expr "]"]
block         ::= "{" { statement } "}"
jump          ::= "goto" label-target | ("gosub" | "gosubstr") [args] label-target
label-target  ::= label | z-label
return-stmt   ::= "return" ["(" expr ")"]

if-stmt       ::= "if" "(" expr ")" block {"elseif" "(" expr ")" block} ["else" block]
for-stmt      ::= "for" "(" {statement} "," expr "," {statement} ")" block
while-stmt    ::= "while" "(" expr ")" block
switch-stmt   ::= "switch" "(" expr ")" "{" {case-clause} [default-clause] "}"
case-clause   ::= "case" "(" expr ")" {statement}
default-clause ::= "default" {statement}

expr          ::= unary {binary-op unary}
unary         ::= {"+" | "-" | "~"} primary
primary       ::= "(" expr ")" | "[" expr {"," expr} "]" | jump
                | integer | character-literal | string-token | label | element-expr
element-expr  ::= element {"." element | "[" expr "]"}
element       ::= identifier [args]
args          ::= "(" [arg {"," arg}] ")"
arg           ::= [identifier "="] expr
```

Binary operators associate from left to right at each level. Precedence increases down the table.

| Level | Operators |
| --- | --- |
| 1 | `\|\|` |
| 2 | `&&` |
| 3 | `\|` |
| 4 | `^` |
| 5 | `&` |
| 6 | `==`, `!=` |
| 7 | `>`, `>=`, `<`, `<=` |
| 8 | `<<`, `>>`, `>>>` |
| 9 | `+`, `-` |
| 10 | `*`, `/`, `%` |

Prefix operators bind more tightly than any binary operator. Profile `7` groups `&&` and `||` at level 1. Both logical operands are evaluated. A list literal has form `list` and contains at least one expression. Parentheses preserve the form and length of a list argument, as in `wipe(option=([1,2]))`.

Assignments use these operators:

```text
=  +=  -=  *=  /=  %=  &=  |=  ^=  <<=  >>=  >>>=
```

### Forms and name resolution

Unqualified element names are looked up in call, scene, then global scope. The call scope contains parameters and local `property` declarations. The scene scope contains scene-local include declarations and scene commands. The global scope contains global include declarations and the profile's built-ins. A member is looked up on the preceding segment's form. Indexing requires an indexed member and an `int` or `intref` expression.

An unresolved single name used as an expression becomes a string after ASCII case folding. The name must contain neither `@` nor `$` and take zero arguments. A standalone ordinary label in an expression has form `label`. Z-label tokens are jump targets and definitions.

An element chain ending in a property of form `int`, `str`, `intlist`, or `strlist` has the corresponding reference form `intref`, `strref`, `intlistref`, or `strlistref`. A chain used as a statement without an assignment must end in a command.

#### Operators and assignment

| Operands | Operators and result |
| --- | --- |
| One `int` or `intref` | Prefix `+`, `-`, `~` yield `int`. |
| Two `int`/`intref` operands | All binary operators in the precedence table yield `int`. |
| Two `str`/`strref` operands | `+` yields `str`. `==`, `!=`, `>`, `>=`, `<`, and `<=` yield `int`. |
| `str`/`strref` followed by `int`/`intref` | `*` yields `str`. |

Plain assignment to `intref` or `strref` accepts the corresponding value or reference. Other assignable forms must match exactly. Compound assignment applies the binary operator and assigns the result. For example, `s[0] *= 3` repeats a string in place.

For bytecode comparisons with the reference Siglus compiler, `s[0] *= 3` records both operand forms correctly in both compilers. The reference compiler writes the left form twice for binary expressions such as `s[0] * 3`.

#### Declaration and call rules

- Scene `property` and `command` return forms default to `int`. Profiles `6`–`8` allow call-local properties outside commands. Other profiles require a command body. Finishing a command definition clears the call scope and exits command context, including after a nested definition.
- A bracketed expression in a property or parameter form must have form `int`. For `intlist` and `strlist`, the expression supplies the runtime length, with zero used when omitted. The form name alone determines a command's return form.
- A global `.inc #command` needs exactly one definition in the directory, even if unused. The definition must match the return form, parameter count, and positional forms. A scene-local `#command` needs a definition in that scene and supplies the call signature there.
- Arguments match the selected command signature. A value parameter of form `int` or `str` can take its scalar reference form. Pass references to reference parameters. Named arguments require recognized names and matching forms. The compiler places positional arguments before named arguments, preserving order within each group. Profile `8` preserves integer references for `wipe(key_skip=...)` and `mask_wipe(key_skip=...)`.
- The declared return form determines the form at call sites. The compiler checks the expression in `return(expr)` without matching it against the declared return form.

#### Control flow and dialogue

- `if`, `elseif`, `for`, and `while` conditions use `int` or `intref`. A `switch` with cases compares integer values to integer values, or strings to strings. The runtime evaluates the condition once and executes the first matching case or the optional `default`. Each branch exits the switch. `break` and `continue` target loops.
- `goto`, `gosub`, and `gosubstr` have forms `void`, `int`, and `str` in expressions. Pass individual integers or strings to `gosub` and `gosubstr` when the result needs to be disassembled or decompiled.
- The compiler rejects selection commands from the active profile in conditions, `case` expressions, command arguments, standalone subroutine-call arguments, and index expressions. See the [profile table](#const-profiles) for the selection command family.
- A bare string statement displays text and allocates a read flag. `【 string-token 】` displays a speaker name. Certain built-in calls also allocate flags according to the selected profile.
- The compiler and LSP warn when syntax nesting exceeds 64 levels or expression-tree height exceeds 128. Macro expansion has separate hard limits.

### Example

`names.inc` declares a command and its integer default.

```text
#define title "ABC"
#command repeat_name(int(3)) : void
```

`main.ss` calls the command and defines it.

```text
#z0
repeat_name()

command repeat_name(property count : int) : void {
    s[0] = title
    s[0] *= count
    set_namae(s[0])
}
```
