# Changelog

All notable changes to this project will be documented in this file.


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
