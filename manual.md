# SiglusSceneScriptUtility Manual

> **CLI only:** This project supports only the `siglus-ssu` command-line interface, provides no support for direct module imports or calls, and accepts no responsibility for any resulting issues.

**Version:** 0.5.8

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
5. [SiglusSceneScript Language Reference](#siglusss-language-spec)
6. [Tips and Troubleshooting](#tips-and-troubleshooting)

---

## Overview

SiglusSceneScriptUtility (`siglus-ssu`) is a command-line tool for SiglusEngine games. It can:

- Compile, extract, disassemble, and decompile scene scripts.
- Export and apply translations, edit saves, and analyze game data.
- Extract and rebuild images, audio, and video, and collect voices by character.
- Patch engine keys and language settings.
- Provide editor support through LSP.

Choose the game's [const profile](#const-profiles) when processing scene scripts. Unsupported engine variants may use different formats.

---

## Installation

### Option 1: Install from PyPI

Requires Python 3.12 or later:

```bash
pip install siglus-ssu
```

Compatible platform wheels include Rust acceleration. Other platforms can use the slower pure-Python wheel or build from source for native acceleration. No initialization or separate constants download is needed.

### Option 2: Install from Source

Requires Python 3.12+, [uv](https://github.com/astral-sh/uv), and [Rust 1.88+](https://rustup.rs/).

Clone the repository, then run from its root:

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

Global options may appear before or after the mode, but must precede `--`. `--const-profile=N` and `--string-xor-multiplier=N` are also accepted.

### Const Profiles

Profiles select built-in types, element codes, command signatures, and compilation rules. The table describes differences from the reference profile in each row; other compilation rules remain unchanged. Game names are compatibility examples.

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

Profile numbers are not chronological. Use the same profile for disassembly, decompilation, compilation, and payload comparison. To identify a profile for a PCK with embedded sources, run `siglus-ssu test Scene.pck` and check the successful result.

Profile `10` has partial mobile API coverage. Its `mobile_*` type names are internal placeholders, not official types for source declarations; emitting these objects as bytecode values is unverified.

### Scene String XOR Multiplier

Use `--string-xor-multiplier N` only when the game's scene-string encoding differs from the profile default. `0` selects plain UTF-16LE strings. This option does not change compression, outer encryption, or the engine executable; `--no-angou` does not disable scene-string XOR.

Use the same profile and multiplier whenever decoding, editing, or recompiling a title. Extraction does not save these settings. A wrong multiplier can produce unreadable text without a format error. One command applies one multiplier to all scenes and both comparison inputs, so inputs using different multipliers must be analyzed separately.

Changing the multiplier rebuilds all `-c --tmp` cached scenes. Operations that do not process scene strings ignore it, including plain extraction, `--dat-repack`, and `--gei`.

For a title using plain scene strings:

```bash
siglus-ssu --string-xor-multiplier 0 -x --disam /path/to/Scene.pck
siglus-ssu --string-xor-multiplier 0 -m /path/to/extracted/chapter1.dat
siglus-ssu --string-xor-multiplier 0 -m --apply /path/to/extracted/chapter1.dat
siglus-ssu --string-xor-multiplier 0 -c /path/to/source/ /path/to/translated.pck
```

### Command Aliases

`siglus-ssu help` and `siglus-ssu version` are aliases for `--help` and `--version`.

After selecting a mode and required sub-operation, use `--` before positional paths beginning with `-`, for example `siglus-ssu test -- --sample.pck`. All options must precede `--`. For an option value beginning with `-`, use an absolute path or prefix it with `./`.

Write long options in full; arbitrary prefixes are not accepted.

### Getting Help

```bash
siglus-ssu --help
```

Mode-specific `--help` shows the same global help page.

---

## Modes Reference

### `-lsp` — Start the Language Server

Starts a stdio language server for `.ss` and `.inc` files. Configure your editor's LSP client to run this command:

```bash
siglus-ssu -lsp [--serial] [--read-sav /path/to/read.sav]
```

| Option | Description |
|---|---|
| `--serial` | Scan the workspace serially instead of in parallel. |
| `--read-sav PATH` | Show saved read states in hover details and clients supporting the `siglus/readFlags` extension. A missing or unreadable save does not prevent startup. |

Features include diagnostics, semantic highlighting, completion, hover, definition and reference lookup, rename, and document symbols. Analysis uses the current scene and same-directory `.inc` files, including unsaved editor changes. Select the game's global `--const-profile` as for compilation.

For pushed diagnostics, the server updates local checks while you edit and reuses the last available link results. Link checks refresh on open or save and when a document closes with unsaved changes. A diagnostic request checks the current workspace.

Workspace indexes are cached between sessions and rebuilt when incompatible. Set `SIGLUS_SSU_LSP_CACHE_DIR` to change the cache location. Defaults are:

- Windows: `%LOCALAPPDATA%\siglus_ssu\lsp-index`, falling back to `%APPDATA%\siglus_ssu\lsp-index`.
- Other platforms: `$XDG_CACHE_HOME/siglus_ssu/lsp-index`, falling back to `~/.cache/siglus_ssu/lsp-index`.

#### Read flags

Read flags are numbered from `0` within each scene. A saved zero means not marked as read; the content may already have appeared before the engine commits the flag, for example at a wait or text-clear operation.

Saved states are shown only when the scene name and flag count match the current source. A count mismatch is reported without applying the saved states. Hover details refer to the text, command, or macro invocation that produced the flag. Multiple flags can share one source location.

Refresh the hover or read-flag request after saving in-game; the server does not actively watch the save file. Editor clients control any background highlighting.

---

### `-c` / `--compile` — Compile Scripts

Compiles `.ss` sources and same-directory `.inc` declarations into a `.pck`. Sources are scanned only in the input directory, not its subdirectories. Keep dot-prefixed sources such as `.scene.ss` and `.defs.inc` when recompiling extracted files.

#### Syntax

```
siglus-ssu -c [options] <input_dir> <output_pck | output_dir>
siglus-ssu -c --gei <input_dir | Gameexe.ini> <output_dir>
siglus-ssu -c --test-shuffle [seed0] [--csv <seed_csv>] <input_dir> <output_pck | output_dir> <test_dir>
```

#### Parameters

| Parameter | Description |
|---|---|
| `<input_dir>` | Directory with at least one named `.ss` script, plus any `.inc`, `Gameexe.ini`, and `暗号.dat` files. `--dat-repack` and `--gei` do not require `.ss` files. |
| `<output_pck \| output_dir>` | An existing directory or a path ending in `/` or `\` receives `Scene.pck`. Any other path is treated as the exact output filename. |
| `--debug` | Keep intermediate files after compilation. Cannot be combined with `--tmp`. |
| `--charset ENC` | Set one encoding for all source files. Default: detect UTF-8 or CP932 per file, with BOM detection for UTF-16 and UTF-32. Shift-JIS aliases such as `sjis` and `shift_jis` select Windows CP932. Other Python codecs are accepted explicitly. |
| `--allow-invalid` | Replace invalid input bytes with U+FFFD, including in `Gameexe.ini` and `暗号.dat`. Without a forced charset or a UTF-16/32 BOM, it tries strict UTF-8 and CP932 before using UTF-8 replacement. Syntax and type errors still fail. |
| `--no-os` | Omit embedded original sources without changing script encryption or compression. |
| `--dat-repack` | Pack existing scene `.dat` files without recompiling. A damaged scene aborts the repack and preserves the existing PCK. Only `Gameexe.dat` and `暗号.dat` may be skipped as auxiliary files. Same-directory `.inc` files supply package command metadata; missing `.inc` files produce a warning. Use `--charset` or `--allow-invalid` for text inputs. A valid `key.txt` takes priority over `暗号.dat` when repacking. Also accepts `--no-os` and `--no-lzss`. |
| `--no-angou` | Disable LZSS compression, outer XOR encryption, and original-source embedding. Does not disable scene-string XOR. Cannot be combined with `--tmp`. |
| `--no-lzss` | Disable LZSS compression and original-source embedding, retaining script encryption. Cannot be combined with `--tmp`. |
| `--serial` | Compile scene scripts sequentially. Packaging can use multiple workers. |
| `--max-workers N` | Positive maximum worker count for parallel scene compilation. The default per-stage allocation is half the available CPUs, limited to 1–16. In a full build with automatic worker counts, Rust can combine the allocations for compilation and compression in one worker pool. On Windows, Python compilation caps explicit values at 61. Ignored with `--serial`. |
| `--set-shuffle SEED` | Set the string-table shuffle seed (`0`–`0xFFFFFFFF`, decimal or hexadecimal; default `1`). Implies `--serial`. Cannot be combined with `--tmp`. |
| `--tmp <tmp_dir>` | Reuse a directory for incremental compilation. Serial builds reuse cached scenes up to the first change and rebuild the rest to preserve string-table order. Concurrent builds cannot share the cache. Cannot be combined with `--debug`, `--dat-repack`, `--no-angou`, `--no-lzss`, `--set-shuffle`, `--test-shuffle`, `--csv`, `--gei`, or global `--const-profile`. |
| `--test-shuffle [seed0]` | Search from `seed0` (default `0`) through `0xFFFFFFFF` for any continuous seed chain that matches the string indexes of every reference DAT in `<test_dir>`. Requires three paths after the optional seed. If the seed is omitted, a supplied `--set-shuffle` value becomes the search start. Cannot be combined with `--tmp` or `--gei`. |
| `--csv <seed_csv>` | With `--test-shuffle`, publish per-scene initial and final seeds with the linked PCK. A directory target receives `test_shuffle_seeds.csv`. |
| `--gei` | Compile only `Gameexe.ini` to `Gameexe.dat`. Output is always a directory. A missing INI produces a warning and succeeds without creating `Gameexe.dat`. Cannot be combined with `--tmp` or `--test-shuffle`. |

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

- **Source encoding:** Use `--charset utf8 --allow-invalid` only to reproduce output made by interpreting invalid UTF-8 with replacement. It can preserve garbled text. Compilation stops at the first DOS EOF character (U+001A); later bytes are ignored. See the [language reference](#siglusss-language-spec) for literal and character rules.
- **Key compatibility:** Keys derived from `暗号.dat` or `angou=text` use CP932 and can differ from official Windows conversion. For existing official files, prefer the raw 16-byte key or matching engine executable. For normal compilation, put the raw key in `key.txt` and remove any higher-priority `暗号.dat` from the input directory.
- **Incremental builds:** Scenes are rebuilt when their source changes or their cached DAT or LZSS file goes missing or changes. Adding, changing, or removing an `.inc`, changing compiler settings, or upgrading the program can require a full rebuild. Failed or interrupted cache updates trigger a full rebuild on the next run.
- **Shuffle search:** String-table order does not affect normal translation work. If no chain matches every scene, the command returns failure before publishing the PCK or CSV. Pass the first scene's reported initial seed to `--set-shuffle` to reproduce the chain.
- **Paths and names:** Paths follow the host filesystem's lookup rules. Multi-file operations reject selected input paths that collide under a fixed Windows filename case mapping, such as `A.ss` and `a.ss` in one directory; unrelated directory entries are ignored. Automatic filename discovery warns about case-colliding candidates and selects one in its usual order, including for embedded configuration sources. Existing output naming rules still apply. Runtime scene names fold only ASCII `A`–`Z` to lowercase; embedded source filenames retain their spelling.

#### Compiling Stats

The final summary reports stage timings and file counts. Compilation and scene compression timings can overlap. `scene_files` is the total scene count. `compiled_scene_files` is the number rebuilt this run. Normal full builds also report source, read-flag, and binary-size statistics.

---

### `-x` / `--extract` — Extract Files

Extracts decoded scene `.dat` files and any embedded original sources from a `.pck`. `--decompile` reconstructs `.ss` / `.inc` without requiring embedded sources.

#### Syntax

```bash
siglus-ssu -x [--disam] [--decompile] <input_pck> [output_dir] [--angou <path|angou=text|key=bytes>]
siglus-ssu -x --disam <input_dir> [output_dir] [--angou <path|angou=text|key=bytes>]
siglus-ssu -x --gei <Gameexe.dat | input_dir> [output_dir] [--angou <path|angou=text|key=bytes>]
```

#### Parameters

| Parameter | Description |
|---|---|
| `<input_pck>` | Scene `.pck` to extract. Encrypted scenes require a valid key source. |
| `<input_dir>` | With `--disam`, scan immediate `.dat` files, skipping non-scene files. |
| `[output_dir]` | Base output directory. Defaults to the input file's directory, or the input directory itself. PCK extraction creates a timestamped subdirectory. |
| `--disam` | Also write `<scene>.dat.txt` disassembly. Cannot be combined with `--gei`. |
| `--decompile` | Write reconstructed `decompiled/<scene>.ss`, plus `decompiled/__decompiled.inc` when needed. Add `--disam` to also write disassembly listings. Requires a complete scene PCK with package metadata, not a single `.dat` or directory. Cannot be combined with `--gei`. |
| `--angou VALUE` | Specify a [decryption key source](#decryption-keys). |
| `--gei` | Restore `Gameexe.ini` from `Gameexe.dat` or its parent directory. Directory lookup uses the fixed Windows filename case mapping and warns about case-colliding candidates. If the output already exists, use `Gameexe_1.ini` and so on. |

The extraction directory is printed after `Output:`. PCK extraction adds numeric suffixes to resolve output-name collisions and reports filenames that are invalid on the output filesystem. To edit embedded sources, work in the extraction directory and pass it directly to `-c`.

If a scene and its embedded key file are both named `暗号.dat`, the key goes in `.siglus-ssu-keys/`. Compilation and repacking can read the key from there.

Decompilation does not automatically detect the profile or recover original macros, comments, or formatting. Recompile `decompiled/` with the same profile and string multiplier, then verify with `-a --payload`. The rebuilt PCK need not be byte-identical. Incomplete disassembly fails decompilation.

**Limitation:** Pass individual integer or string arguments to `gosub` and `gosubstr`. List-literal arguments can produce output that cannot be fully disassembled or decompiled.

FlixEngine scenes use profile `10`. Flix resource PCK containers support plain extraction only.

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

Verify that no scenes are missing or added and no payload differences or unavailable results remain. Exit status `0` alone does not establish equality; see [Payload Comparison Results](#payload-comparison-results).

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

Use `--angou VALUE` as the final mode-specific option, with a separate, nonempty value:

| Value | Meaning |
|---|---|
| File path | Read a key from `暗号.dat`, `key.txt`, `Scene.pck`, or `SiglusEngine*.exe`. |
| Directory path | Search that directory's immediate files. |
| `angou=text` | Derive a key from a literal `暗号.dat` first line. |
| `key=bytes` | Supply a 16-byte key. Prefer explicit `0xNN` tokens to avoid numeric ambiguity. |

Decryption tries the explicit key source first, then embedded `key.txt` or `暗号.dat`, the current directory, and its parent. Directory search order is `Scene.pck`, `Scene*.pck`, `暗号.dat`, `key.txt`, then `SiglusEngine*.exe`; searches are not recursive. An explicit path disables parent-directory probing. An explicit source that is missing, malformed, or contains no key is an error; a valid key that fails decryption allows lower-priority candidates.

When compiling or decrypting an encrypted `Gameexe.dat`, each nonblank line after comment removal must be a configuration assignment such as `#WINDOW_XSIZE=640`. The `#` prefix is optional. Names start with an ASCII letter, digit, or underscore and may also contain periods, square brackets, hyphens, spaces, and tabs. Values may contain Unicode text. The format has no checksum to distinguish keys that produce syntactically valid text. Decryption fails if candidate keys produce different valid texts.

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
| `--type N` | Output database type (`0`–`2147483647`; default `1`). Type `0` strings must be encodable as CP932; other types use UTF-16LE. |
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
| `<voice_dir>` | One `.ovk` or a directory containing `.ovk` files, scanned at the immediate level only. |
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
| `<label>` | Non-negative decimal number, optionally prefixed with `z` or `#z`. |

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
siglus-ssu -g --c [--type N] [--refer <ref_g00 | ref_dir>] <input_png | input_jpeg | input_json | input_dir> [output_g00 | output_dir]
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
| `--refer <ref_g00 \| ref_dir>` | Update an existing G00. Directory input requires a reference directory. A single input accepts a reference file or directory. Directory lookup uses the fixed Windows filename case mapping and warns about case-colliding candidates. With no output path, the selected reference is overwritten. |
| `:cutNNN` | Select a type2 cut for merging, for example `sprite.g00:cut002`. |

Extraction and creation scan directory inputs at the immediate level only. When creating a new type2 layout, extraction fails if an existing cut PNG is unreadable or has a different size from the untrimmed cut.

#### Create and Update

Without `--refer`, PNG creates type0 and JPEG creates type3. Creating or updating type0 sets alpha to 255. Use `--type 2` with a `.type2.json` layout to create type2. Creating type1 is not supported.

With no output path, creation writes beside the input and updates overwrite the reference. Outputs cannot overwrite a source image, layout, or another target's reference, and must resolve to distinct files. An in-place update verifies the reference bytes immediately before replacement. Concurrent updates to the same output directory wait up to 30 seconds for the active update. After an interrupted update, remove `.siglus-g00.lockdir` only after confirming no update is running.

Back up original assets before updating them. JSON layouts cannot be combined with `--refer`. To update an individual cut through a reference directory, name its replacement `<basename>_cut###.png`.

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

Pass the JSON, not an individual cut PNG, to rebuild a multi-cut image. Extraction preserves RGB beneath transparent pixels; rebuilding uses the edited PNG values as supplied.

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
- `cuts` is ordered by index; `null` leaves a hole.
- `source` is relative to the JSON file; `/` and `\` are accepted as separators.
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

Extracts Ogg video from OMV and wraps Theora video as OMV without re-encoding or converting colors/transparency. Extraction preserves embedded audio. Creation keeps only the first Theora video stream. Both operations reject Ogg streams with missing pages, truncated pages, or invalid page checksums.

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

Inspect the original with `-v --a` and keep its mode when extracting. The Ogg file does not store the OMV mode. Standard modes use Theora 4:4:4 planes:

| Mode | Layout |
|---|---|
| `0` | B, G, R planes; opaque. |
| `1` | B, G, R planes, each followed by an alpha segment. |
| `2` | Full-range BT.601 Y, U, V. |

For mode `1`, visible height `H` needs Theora picture height `H + ceil(H / 3)`. The first `H` rows of each plane hold color. Concatenate the following alpha segments in plane order and take the first `H` rows as alpha. A 1080-row image needs a 1440-row encoded picture.

Ordinary players treat planes as YUV, so mode `0`/`1` needs color/alpha reconstruction for normal viewing. Neither `--mode` nor `--refer` performs that conversion. Wrapping ordinary YUV video with a mode `0`/`1` reference produces an incorrect picture. Other numeric modes are accepted as metadata but are outside the standard layouts above.

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
| `--loc 1` | Restore region detection previously disabled by this tool. |

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
siglus-ssu [--const-profile N] test [--allow-invalid] [--serial] [--report-json FILE] <input_pck|input_dir>
siglus-ssu --const-profile N test --decompile [--serial] [--report-json FILE] <input_pck|input_dir>
```

| Option | Description |
|---|---|
| `--decompile` | Reconstruct source without using embedded sources, rebuild it, and compare payloads. Requires an explicit global profile; uses strict UTF-8 without retries. |
| `--allow-invalid` | With an explicit profile in embedded-source mode, compile as UTF-8 with replacement for invalid bytes. Not accepted with `--decompile`. |
| `--serial` | Disable parallel compilation during rebuilds. |
| `--report-json FILE` | Write results and timings as JSON. Cannot overwrite an input PCK or a file read for its key. |

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

## SiglusSceneScript Language Reference

These rules describe source accepted by `siglus-ssu -c`. The selected profile supplies available types (`form`), built-in properties and commands, and profile-specific constraints.

### Source Files

Each scene uses its `.ss` file and all same-directory `.inc` files. Includes are processed in ASCII-lowercased filename order.

Source encoding is detected per file or selected with `--charset`. Invalid bytes fail unless `--allow-invalid` is enabled. Compilation ignores bytes after the first DOS EOF character (U+001A), ignores leading BOM characters, and normalizes CRLF/lone CR to LF. No Unicode normalization is performed.

### Processing Order

1. Load same-directory `.inc` declarations.
2. Remove scene comments, fold ASCII case, process conditional directives, and collect `#inc_start ... #inc_end` regions.
3. Process those local declarations and expand replacements in scene text.
4. Check scene syntax/types and directory-level command definitions, then build the PCK.

Scene-level conditions run before local include declarations, so they cannot see names declared in those regions. Every global `.inc #command` must have exactly one implementation in the directory, even when each scene otherwise compiles successfully.

### Character-level processing

#### Case folding

ASCII keywords, identifiers, labels, and directive names are case-insensitive. `A`–`Z` are lowercased outside strings, character literals, and comments; non-ASCII characters are unchanged.

#### Comments

Both scene text and `.inc` text accept these comment forms:

- `;` to end of line;
- `//` to end of line;
- `/* ... */` block comments.

`/* ... */` does not nest. An unterminated block comment is invalid. Comment openers inside single-quoted and double-quoted literals are ignored.

In scene files, `.inc`, and `Gameexe.ini`, delimiters may share a `*`: `/*/` is a closed empty comment. In `/*/text*/`, `text*/` remains outside the comment. Use `/* text */` to comment out text.

#### Conditional compilation

Both scene text and `.inc` text support:

```text
#ifdef <word>
#elseifdef <word>
#else
#endif
```

1. `#ifdef` and `#elseifdef` test name existence, not numeric truth.
2. Nesting is limited to 15 levels. Unmatched or unclosed directives are errors.
3. A tested name may start with an ASCII letter, CP932 double-byte character, `_`, or `@`; later characters may also be digits.
4. Only the innermost condition controls text inclusion. Nested conditions do not inherit an enclosing false state.

For example, if `inner_present` exists but `outer_missing` does not, `kept` is included:

```text
#ifdef outer_missing
#ifdef inner_present
kept
#endif
#endif
```

#### `#inc_start` / `#inc_end`

Use `#inc_start` and `#inc_end` to place local `.inc` declarations inside a scene file. Blocks cannot nest. Unmatched or unclosed blocks are errors.

#### Source metadata comment

If the first line after source decoding begins with this exact text prefix:

```text
// #SCENE_SCRIPT_ID = dddd
```

`dddd` is four decimal digits recorded as scene metadata. Later text on the first line is ignored for this ID.

### Lexical structure

#### White space and newlines

Whitespace consists of spaces, tabs, and newlines. A newline does not terminate a statement. Semicolons start comments, not statement terminators.

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

- A lone `#` is accepted as an ordinary label.
- Z-labels use 1–3 ASCII digits. Profiles `7` and `8` accept values below `100`; other profiles accept values below `1000`.
- `#z0`, `#z00`, and `#z000` occupy the same numeric label slot, but a jump reference must exactly match the definition's spelling. `#z1234`, and `#z100`–`#z999` in profiles `7`/`8`, are ordinary labels.
- Labels must be uniquely defined and all references must resolve. Every scene must define a Z-label with numeric value `0`.

#### Integer literals

Three forms of integer literal are accepted:

```text
decimal ::= digit { digit }
binary  ::= "0b" { "0" | "1" }
hex     ::= "0x" { hex-digit }
```

Integers are signed 32-bit values with wrapping overflow. The minus sign is a unary operator. Bare `0b` and `0x` are accepted as zero.

#### Character and string literals

Single-quoted and double-quoted literals may not cross a physical line. The only accepted escape spellings are:

- `\\`
- `\n`
- `\'` inside single-quoted literals, or `\"` inside double-quoted literals

In double quotes, `\n` becomes a newline. In single quotes, `'\n'` yields the character `n`. A single-quoted literal must produce exactly one character and has integer type; a double-quoted literal has string type.

#### Fullwidth / double-byte bare strings

Runs of Windows CP932 double-byte characters, excluding `【` and `】`, can be written as unquoted strings:

```text
"こんにちは"
こんにちは
```

Non-ASCII characters outside that set need quotes, even in UTF-8 source. Speaker names can use `【名前】`.

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
| 1 | `\|\|` | left |
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

Profile `7` treats `&&` and `||` as the same precedence level, evaluated left to right. All other profiles use the table above.

### The `.inc` declaration language

Global `.inc` files and scene-local include regions accept the same declarations:

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

#### Declaration Names

- `#replace` / `#define` names end at space, tab, or newline.
- `#define_s` names end at tab or newline and may contain spaces.
- `#property` names also end at `:`; `#command` names also end at `(` or `:`.
- Property and command names may use characters outside the ordinary scene identifier set.
- Macro names must begin with `@`.
- All declarations share one namespace. Duplicate names fail; successful declarations immediately affect later `#ifdef` / `#elseifdef` tests.

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

`#replace` inserts its text without immediately expanding the inserted result again. `#define` and `#define_s` immediately rescan their result for further replacement.

The longest matching name wins within the ordinary definitions or macro parameters. If both groups match, the lexicographically larger candidate name wins. Declaration order does not determine priority.

#### `#macro`

```text
macro-decl ::= "#macro" macro-name ["(" macro-param {"," macro-param} ")"] replacement-text
macro-name ::= "@" <non-space-sequence>
macro-param ::= param-name ["(" default-text ")"]
```

- Macros substitute text. Arguments and defaults are expanded before substitution.
- Parentheses, when present, must contain at least one parameter; empty `()` is rejected.
- Argument splitting respects nested parentheses and quoted literals.
- The body expands with its parameter values, and the inserted result is not immediately rescanned.
- Repeated parameter names use the first occurrence's argument/default. Later occurrences still count as parameters and their values are expanded.

**Expansion limits:** Macro nesting is limited to **128 levels**. Text, argument, and body expansion stops after more than **10000 consecutive scanning steps** without a new minimum remaining-text length. Include `#expand` processing applies the same rule in declaration steps. These are progress limits, not limits on total macros or declarations in a file.

Exceeding a limit fails compilation or LSP analysis. Correct cyclic definitions or reduce expansion depth before retrying.

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

- Default return form: `int`.
- Parameters specify forms and defaults, without names.
- Parentheses, when present, must contain at least one parameter.
- Every parameter after the first default must also have a default.
- `int` and `str` defaults are accepted, but only integer defaults can be omitted at calls. Omitted string defaults cause compilation failure.

#### `#expand`

```text
expand-decl ::= "#expand" replacement-text
```

`#expand` immediately expands its text and processes the result as `.inc` declarations.

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

Rules:

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
3. `form[exp]` in scene `property` and `command` parameter declarations requires an `int` expression but does not give call-local properties a fixed array size as `.inc #property` does.

A bracketed expression after a `command` return type is ignored. The return type is determined by `form-name`.

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
- parentheses around a list argument do not change its element count or type information; for example, `wipe(option=([1,2]))` and `wipe(option=[1,2])` are equivalent;
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

Available members in a chain such as `a.b[c].d(...)` depend on the preceding segment's type and the selected profile.

#### Reference forms for properties

Property expressions use the corresponding reference type:

- `int` -> `intref`
- `str` -> `strref`
- `intlist` -> `intlistref`
- `strlist` -> `strlistref`

Therefore the left-hand side of an assignment shall be an element expression that resolves to a reference form.

#### Unresolved Names as Strings

An unresolved single-segment name with no arguments and no `@` or `$` is treated as a string literal of the same spelling. Other unresolved element names are errors.

### Types and static constraints

#### Analysis depth warnings

Syntax nesting beyond `64` levels or expression-tree height beyond `128` produces a warning; compilation and LSP analysis continue. These are separate from hard [macro expansion limits](#macro).

#### Unary and binary operators

Operator types:

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

1. profiles `0`–`5`, `9`, and `10` allow `property` only inside `command`. Profiles `6`–`8` also allow call-local properties outside commands;
2. conditions of `if`, `for`, and `while` shall be `int` or `intref`;
3. the `switch` condition shall be `int`, `intref`, `str`, or `strref`, and each `case` value shall belong to the same integer family or string family as the condition;
4. the form of `goto` as an expression is `void`; `gosub` is `int`; `gosubstr` is `str`;
5. `continue` and `break` are invalid outside loops;
6. certain commands marked by the active profile as selection-related shall not appear in conditions, ordinary arguments, goto arguments, or index expressions;
7. `name-stmt` emits a name-display event, and `text-stmt` emits a text-display event and consumes a read-flag slot.

In profiles `0`–`5`, `9`, and `10`, a local `property` after a nested `command` definition is also rejected unless inside another command definition. Profiles `6`–`8` allow it.

#### Matching command definitions to declarations

A scene command can be local or implement a global `.inc #command`. Global implementations must match the declared return form, parameter count, and positional parameter forms. Parameter names and defaults are not compared.

#### Return Values

Call-site type checking uses the declared return form. The compiler does not check whether `return(exp)` actually matches that form.

#### Named arguments

Named arguments are accepted only by commands with named parameters. Unknown names and type mismatches are errors.

### Whole-file and directory-level constraints

#### Labels and z-labels

A scene file shall satisfy:

1. ordinary labels are not redefined;
2. z-labels are not redefined;
3. every referenced label and z-label is defined;
4. `#z0` is present;
5. every scene-local `command` declaration is eventually defined in the same file.

#### Directory-level linking of global `.inc #command`

Every global `.inc #command` needs exactly one scene implementation, even when unused. Missing or duplicate implementations fail linking.

## Tips and Troubleshooting

### Unexpected Tokens During Compilation

Quote text containing commas or parentheses when it should be one argument:

```ss
set_namae("Hello, world")
```

### Mixed-Form String Multiplication

String-by-integer `*` expressions, such as `set_namae("ABC" * 3)`, generate different bytecode from the official compiler. For matching output under both compilers, assign to a string variable and use `*=`:

```ss
s[0] = "ABC" s[0] *= 3 set_namae(s[0])
```

Using `s[0] = s[0] * 3` does not avoid the compatibility issue.
