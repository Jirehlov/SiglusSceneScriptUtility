# Changelog

All notable changes to this project will be documented in this file.


## [v0.1.15] - 2026-04-05

- **New Mode:** Added `-lsp` stdio language-server mode for SiglusSceneScript. The new server provides compiler-backed diagnostics, completions, hover, go-to-definition, references, rename, semantic tokens, and document symbols for `.ss` and `.inc` files.
- Renamed the Python package namespace from `siglus_scene_script_utility` to `siglus_ssu`. The `siglus-ssu` console entry point stays the same, but Python imports, the Rust extension module path, and pure-wheel packaging now use the new package name.
- Changed `const.py` loading to validate the installed file on load, reload cleanly when the selected `--const-profile` changes, and resolve package version metadata through the renamed `siglus_ssu` package path.
- `-k --koe` now reports total referenced voice duration together with counted and failed duration items. This is backed by new Ogg duration parsing helpers and OVK sample-count exposure.


## [v0.1.14] - 2026-03-28

- Added a scene decompiler and shared decompile-hints pipeline. `-x --disam` and `-a --disam` now emit readable `.dat.txt` output together with reconstructed `decompiled/*.ss` scripts and `decompiled/__decompiled.inc`, and print separate disassembly / hints / decompile timing totals.
- Expanded `.dat` trace and disassembly metadata with scene IDs and names, `namae` and read-flag definitions, richer `CD_TEXT` and `CD_NAME` string linkage, and annotated command-call metadata. These traces now back decompilation, semantic payload comparison, and trace-based KOE collection.
- Changed `-a --payload` for `.dat` and `.pck` comparisons to use normalized decoded `scn_bytes` semantics instead of a raw decoded-payload SHA-1, so string-pool ID differences no longer count as changes when the resolved text is the same.
- Added `.pck` analyze statistics for `scene_files`, `CD_TEXT`-based dialogue line and character totals, `.ss`-based dialogue totals when embedded original sources are present, and partial-parse counters such as `parsed_scene_files` and `ss_failed_files`.
- Added `.ss` textmap `kind` classification in exported CSVs: `1 = dialogue`, `2 = speaker name`, `3 = other text`.
- Changed KOE collection to operate on disassembly traces instead of `.ss` text scanning, and added direct `.pck` input support.
- Fixed scene decryption key resolution to prefer the current `.pck`'s embedded original sources before falling back to sibling files in the same directory, and generalized local `.pck` probing so it no longer depends on the filename being exactly `Scene.pck`.
- `init` now preserves verified downloaded `const.py` bytes exactly instead of rewriting normalized text.
- Added `scripts/eval_all_pcks_payload.py` for batch end-to-end payload regression evaluation across `.pck` files.
- Updated GitHub Actions workflows to newer `checkout`, `setup-python`, `upload-artifact`, and `download-artifact` action versions.


## [v0.1.13] - 2026-03-18

- Added built-in const profiles, `--const-profile`, and version-aware `init` ref resolution.
- Added `--no-lzss`, `-x --disam <input_dir> [output_dir]`, and optional default output directories for extract mode.
- Added `-a --payload` scene comparison for `.dat` and `.pck`, now defined as comparing the SHA-1 hash of decoded/decompressed `scn_bytes`.
- Reworked disassembly metadata and scene logging, including scene SSID display, richer `.dat` disassembly context, and updated compare/extract statistics.


## [v0.1.12] - 2026-03-08

- `-g --c` now supports true create mode: create new `.g00` files directly from PNG/JPEG/type2 JSON inputs (type0/type2/type3).
- `init` now verifies downloaded `const.py` against a built-in SHA-512 allowlist before writing.
- Release workflow now publishes an additional pure-Python wheel artifact (`py3-none-any`).
- Textmapping mode is now more robust.


## [v0.1.11] - 2026-03-04

- **New Mode:** `-p` (Patch Tool) for patching `SiglusEngine.exe` (altkey/lang translation).
- **New Mode:** `-d` (DB Tool) for exporting, applying, and analyzing `.dbs` database files.
- Completed OMV video format support, including metadata extraction and `.ogv` to `.omv` packing.
- Added `-s --c` mode for repacking audio formats.
- Added manual files.
