# Changelog

All notable changes to this project will be documented in this file.


## [v0.4.0] - TBA
- Reviewed by Fable 5 and GPT-5.6 Terra and GPT-5.6 Sol.
- Added LICENSE.
- Changed internal cache, analysis, and payload digests from MD5/SHA-1 to SHA-256, invalidating old compile and LSP caches without compatibility fallback.
- Fixed G00 type2 merging to preserve straight-alpha RGB and use the center coordinates of the selected cut.
- Changed `--test-shuffle` to return failure when later scene verification does not match, while still building the requested output.
- Changed `siglus-ssu test` success results from `PASS` to `EXACT` for byte-identical `.pck` files and `PAYLOAD_SAME` for different `.pck` bytes with matching normalized payloads.
- Changed KOE character directories to use distinct percent escaping for invalid path characters, trailing spaces or dots, reserved names, and empty names.
- Fixed `.ss` text-map identity and current-span resolution, rejected duplicate or overlapping replacements before write-back, and reduced overlap validation to `O(n log n)`.
- Fixed disassembly table isolation across const profiles, removed the duplicate decompiler element cache, and made automatic compile temporary directories unique across concurrent runs.
- Changed language patch presets to verify complete changes on a working copy and write atomically, with explicit `--allow-partial` recovery behavior and symbolic-link rejection.
- Added six-field JSON language configurations and byte-identical language-patch reversion, moved runtime strings into a dedicated read-only PE section, stored configuration and undo data in an EOF overlay, synchronized compiler-inlined literal lengths when retargeting strings, and fixed charset filtering for both EAX- and ESI-based `ENUMLOGFONT` loops.
- Changed DBS creation to reject unencodable strings, fixed TCR type-zero parsing and expected CLI format errors, and made PCK sample caches verify Git blob hashes without obsolete sidecar metadata.
- Documented case-insensitive scene lookup and case-preserving embedded source metadata, made runtime input reads prefer exact paths before case-insensitive fallback, rejected case-colliding directory enumeration under Windows filename rules, and included the `siglus-ssu` version in persistent compile-cache compatibility checks.
- Rejected analyze and DBS options that do not apply to the selected input or mode instead of silently ignoring them.
- Aligned the Python and Rust frontends with the official compiler for scene-local commands, exact Windows CP932 decoding/encoding, and CP932 double-byte character classification.
- Made native LSP token validation and overlap tracking linear or logarithmic instead of quadratic on large multi-line and single-line documents, bounded its casefold cache, and preserved invalid-character diagnostics and nested macro occurrences.
- Serialized writers of an explicit compile `--tmp` cache to prevent concurrent cache corruption.
- Hardened CLI failures for invalid output directories, unsupported sound extraction inputs, textmap file types/decoding, and invalid analyze option combinations; sound trimming now uses an invocation-unique temporary directory without deleting pre-existing output content.
- Fixed the PyPI README documentation links and aligned both manuals with per-file source encoding detection and the pure-Python fallback wheel.


## [v0.3.7] - 2026-07-07
- Better LSP.
- Added a Rust native compile backend for `siglus-ssu -c`, used automatically when available and supported by the selected compile options, with Python fallback.
- Added Rust native acceleration for `siglus-ssu -a --payload` semantic scene-bytecode comparison, with automatic Python fallback when native payload scanning is unavailable.
- Changed compile-mode scene-name packing to mirror the official compiler's ASCII-only lowercase normalization, preserving non-ASCII letters such as fullwidth `ＥＤ` in rebuilt `.pck` scene tables.
- Changed global `--legacy` to force only the Python compile backend while keeping native helpers such as LZSS enabled.
- Added global `--legacy-full` to restore the old full-legacy behavior that disables all Rust native acceleration.
- Changed `.dat` disassembly so `--disam` writes only `.dat.txt`; use `siglus-ssu -x --decompile <input_pck>` to additionally emit reconstructed `decompiled/*.ss` output from a complete `.pck`.
- Changed `siglus-ssu -m --disam <dir>` and `--disam-apply <dir>` to resolve the scene key candidates once for the input directory and reuse them for every `.dat` file in the scan.


## [v0.3.6] - 2026-06-14
- Security updates.
- Added --angou for more modes.
- Added `siglus-ssu -g --x --trim` to crop extracted PNG transparent or fully opaque background-color edges and JPEG background-color edges, preserving untrimmed JPEG payloads and skipping type2 JSON sidecars because trimmed images are not rebuild layouts.
- Added `siglus-ssu -g --m --trim` to crop transparent or opaque-background edges from merged G00 PNG output.
- Changed `siglus-ssu -a` `.pck` comparison output to keep non-OS section rows before original-source rows instead of interleaving both groups during ID sorting.


## [v0.3.5] - 2026-06-01
- Happy birthday, Koyomi!
- Fixed `siglus-ssu -k` `koe_master.csv` speaker inference so rows only use same-line trace metadata, anonymous voiced text no longer inherits nearby or same-`koe_no` speakers, callsites whose OVK entry is missing keep their known `koe_no`, and all CSV rows remain sorted by `koe_no`.


## [v0.3.4] - 2026-05-28

- Improved LSP protocol compatibility by negotiating client position encodings, returning range-aware completion edits, normalizing completion item kinds to client capabilities, supporting work-done progress cancellation, and validating document URIs and request shapes more defensively.
- Hardened LSP workspace indexing by matching overlay paths case-insensitively where the platform does, validating persistent cache payloads more strictly, deriving cache files from input signatures, isolating protocol stdout from worker output, and terminating process-pool workers promptly when scans are cancelled.
- Added `duration_sec` to `koe_master.csv`, using OVK entry sample counts and Ogg sample rates to write per-KOE voice durations in seconds, including rows generated by `--stats-only`.
- Updated the English and Chinese manuals for the LSP protocol behavior and the new `koe_master.csv` duration column.
- Changed `siglus-ssu -c --tmp` to reject incompatible compile options: `--debug`, `--dat-repack`, `--no-angou`, `--no-lzss`, `--set-shuffle`, `--test-shuffle`, `--csv`, `--gei`, and global `--const-profile`.
- Changed `siglus-ssu -c --tmp` to reuse cached `.lzss` outputs for unchanged `.ss` files when `.inc` files are unchanged.
- Removed `siglus-ssu -c --lzss-level`; LZSS compression now uses the fixed default level.
- Changed `siglus-ssu -a --readall` and `siglus-ssu -a --apply` to create a non-overwriting `.bak` backup before rewriting `.sav` files.
- Changed `siglus-ssu -a --gei` to reject incompatible analyze flags instead of silently ignoring them.
- Added a `SCENE_SCRIPT_ID`/`ID` column to `siglus-ssu -a` `.pck` analysis and `.pck` comparison tables for embedded `.ss` source chunks, and made `.pck` comparisons treat source IDs as comparison data.
- Simplified `siglus-ssu -k` OVK selection to the flat top-level `.ovk` layout used by Siglus voice archives.


## [v0.3.3] - 2026-05-17

- Fixed LSP cold workspace scans after package upgrades by flushing standard streams before starting scan worker processes.


## [v0.3.1] - 2026-05-17

- Fixed duplicate buffered output parallel workers started, and added a regression test for flushing standard streams before process-pool startup.
- Added `siglus-ssu -c --test-shuffle --csv <seed_csv>` to write per-script initial and final MSVC shuffle seeds while rebuilding matched scene scripts.
- Changed `siglus-ssu -a --angou <value>` to accept a literal angou string directly when the argument is not an existing path.
- Added `siglus-ssu -s --x --trim` support for `.nwa` BGM extraction, trimming decoded PCM to `.wav` from Gameexe loop points and requiring `ffmpeg` only when `.owp` files are trimmed.


## [v0.3.0] - 2026-05-04

- Changed `siglus-ssu -p --lang` to remove the old `chs`/`eng`/JSON patcher and add fixed `cjk` and `cjk-path` presets using PE string relocation for active language and path references.


## [v0.2.8] - 2026-04-28

- Added `siglus-ssu -a --apply <global.sav>` support to read the sibling `global.txt` and write supported `G`, `Z`, `cg_table`, `bgm_table`, and `chrkoe.look_flag` entries back into `global.sav` in-place.
- Aligned LSP with 3.17 standards.


## [v0.2.7] - 2026-04-27

- Optimized LSP.
- Changed `-k --koe` to preserve multiple dialogue texts that share the same `koe_no`, write separate `koe_master.csv` rows per `koe_no`/text pair, and report `KOE multi-text` summary counts with the affected `koe_no` values.
- Added `-a --angou <Scene.pck>` support to extract embedded `暗号.dat` from the `.pck` original-source area before deriving the `exe_el` key.
- Added `siglus-ssu test <input_pck|input_dir>` to extract, in-place recompile with `const-profile` fallback, payload-compare with focused failure output, report total/summary step timings, and clean up round-trip tests for `.pck` files with embedded original sources.


## [v0.2.6] - 2026-04-24

- Added `-s --a <old.ovk> <new.ovk>` support to compare OVK archives by KOE number, size, sample count, and decoded Ogg payload content.
- Changed `-a --payload` for `.pck` and `.dat` comparisons to split payload differences into `text_only` resolved-text changes and `real_diff` non-text scene-bytecode changes, while keeping the original full payload hash semantics for equal versus non-equal payloads.


## [v0.2.5] - 2026-04-23

- Added `-t` / `--tutorial` mode to build a conservative static tutorial graph JSON from `Scene.pck`, write a sibling `tutorial_viewer.html`, print generation progress, and try to auto-open the viewer in the default browser.
- Added `siglus-ssu -a --readall <global.sav>` support. It now unlocks engine-managed global collection fields in-place, including `cg_table`, `bgm_table`, and `chrkoe.look_flag`, while leaving unrelated generic global flag arrays untouched.
- Added `siglus-ssu -p --info <input_exe>` to print a read-only preview of patchable `ALTKEY`, `LANG`, and `LOC` slots without writing a file.
- Changed built-in `-p --lang chs` / `eng` presets to use explicit `charset1` / `charset2` pairs, rewrite standalone locale/code/path slots more conservatively, rewrite all fixed-length `Gameexe.dat` hits so user-facing prompt text stays in sync, and refuse unknown charset-slot layouts instead of guessing.


## [v0.2.4] - 2026-04-19

- Added `-s --play` support for legacy `.nwa` BGM files.
- Changed the compile summary heading from `Stage Timings` to `Compiling Stats`, and added `inc_files`, `scene_files`, `compiled_scene_files`, full-compile macro totals/unused counts for `#replace`, `#define`, `#define_s`, `#macro`, plus `read_flags`, `read_flags_scenes`, and `top5_read_flags_scenes`.
- Added `.pck` analyze output for `read_flags`, `read_flags_scenes`, and `top5_read_flags_scenes`, using the decoded scene `.dat` payloads inside the archive.


## [v0.2.3] - 2026-04-12

- Changed `-s --play` to use a full-screen terminal UI with a live progress bar, a scrollable playlist view, full-path header display, and cleaner in-place redraws instead of interleaved `player>` prompt printing.


## [v0.2.2] - 2026-04-12

- Changed compile mode to remove `--parallel`, keep parallel compilation as the default, add `siglus-ssu -c --serial` to force serial compilation, and remove the unused internal `stop_after` stage cutoff hook from the compiler pipeline.
- Changed LSP workspace scanning to run in parallel by default, and added `siglus-ssu -lsp --serial` to force serial scanning when needed.
- Added `patch --loc` support to toggle SiglusEngine region detection, locating the guard routine through PE imports and call flow instead of relying on fixed Japanese-only strings.
- Changed `const.py` loading to prefer packaged `src/siglus_ssu/const.py` before the external data directory, allow direct use when a packaged const is present, bind `siglus_ssu.const` on import, and report the actual search paths on load failure.
- Added and expanded sound-mode `--play` for looped BGM preview: it now accepts a single `.owp`/`.ogg` file or a directory playlist, accepts either `Gameexe.dat` or `Gameexe.ini`, auto-detects a nearby Gameexe source when omitted, skips files without matching `#BGM.*` entries, and uses `ffplay` to start at `start` before looping the `repeat` → `end` region indefinitely.


## [v0.2.1] - 2026-04-06

- Changed `.pck` analysis so word counting no longer runs implicitly. Use `-a --word <input_pck> [output_csv]` to generate word-count output and CSV files, with one row per decoded scene `.dat` and one row per embedded `.ss` source.
- Added a deterministic built-in word-count rule so mixed CJK and non-CJK text is counted consistently across platforms.
- Added `-k --stats-only` to collect KOE statistics and write CSV output without extracting audio files.
- Added `-k --single <koe_no>` to extract only one specific KOE entry.
- `.pck` analysis now also prints the angou data file when an embedded or adjacent source is available, matching compile-mode summary output.


## [v0.2.0] - 2026-04-05

- Improved LSP mode.


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
