# SiglusSceneScriptUtility

This utility aims to reproduce SiglusEngine's scene script compilation bit-for-bit, along with other related (and unrelated) features.

## Installation

This project uses [uv](https://github.com/astral-sh/uv) for project management.

### 1. Install `uv`

Choose the command for your operating system:

**Windows (PowerShell):**
```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral-sh.uv.run/install.ps1 | iex"
```

**macOS / Linux:**
```bash
curl -LsSf https://astral-sh.uv.run/install.sh | sh
```

### 2. Install Rust Toolchain
Since this project uses a Rust native extension, you need the Rust compiler installed:
- Visit [rustup.rs](https://rustup.rs/) and follow the instructions for your platform.

### 3. Setup Project
Run the following command in the project root to build the Rust extension and sync dependencies:
```bash
uv sync
```

## Usage

You can use the `siglus-ssu` command directly through `uv run`:

```bash
# Display help
uv run siglus-ssu --help
```

Common modes and examples:

| Mode | Description | Example |
| --- | --- | --- |
| Compile | Build scripts into `.pck` | `uv run siglus-ssu -c <input_dir> <output_dir>` |
| Extract | Unpack `.pck` files | `uv run siglus-ssu -x <input_pck> <output_dir>` |
| Analyze/compare | Inspect or diff files | `uv run siglus-ssu -a <file1> [file2]` |

## Project Structure

- `src/siglus_scene_script_utility/`: Core Python package logic.
  - `rust/`: Rust native extension source (`siglus_ssu_native`).
- `tests/`: Test and benchmark scripts.
- `pyproject.toml`: Modern project configuration using `maturin` backend.



## Development

### Code Quality

This project maintains code quality standards using modern tooling for both Python and Rust.

**Python (checked via [Ruff](https://docs.astral.sh/ruff/)):**
```bash
# Check for issues
uv run ruff check .

# Auto-fix fixable issues
uv run ruff check . --fix
```

**Rust (checked via [Clippy](https://doc.rust-lang.org/clippy/)):**
```bash
cd src/siglus_scene_script_utility/rust
cargo clippy -- -D warnings
```

### Formatting

To ensure consistent code style, run the formatters:

**Python (via [Ruff](https://docs.astral.sh/ruff/formatter/)):**
```bash
uv run ruff format .
```

**Rust (via [rustfmt](https://github.com/rust-lang/rustfmt)):**
```bash
cd src/siglus_scene_script_utility/rust
cargo fmt
```

### Testing

Run the test suite using `pytest`:

```bash
uv run pytest
```

**Rust:**
```bash
cd src/siglus_scene_script_utility/rust
cargo test
```

### Benchmarks

Run the benchmark script to measure performance improvements:

```bash
uv run python tests/benchmark.py
```

## Tips

If you type something in a .ss file that would break tokenization, wrap it in double quotes so it's treated as a literal.

Some official builds shuffled their strings with a magical initial seed. If you want to reproduce the shuffle bit-by-bit (you don't have to, though. It won't affect your engine's parsing), set the initial seed with --set-shuffle. If you don't know the seed, try to find it with --test-shuffle, which is expected but not guaranteed to be there. Some known seeds are as follows,

| PCK | initial seed |
| --- | --- |
| [augment_protocol_hZTHqv8A_DL](https://www.virustotal.com/gui/file/1e5d5d094e19df0e7b160022fd34ab8fb25d4af7882935692bc0182c0ad21dc8) | 1769178361 |
| [prima02_Vwm4NjRVFPnf_Tr](https://www.virustotal.com/gui/file/968e8c2d2952ef671e9736de383361b393ea161d5948ae15c72ffb5a1ea7edde) | 1556068939 |
| [prima01_wM5fRc2F_TR](https://www.virustotal.com/gui/file/17b401045e582e6a28217286de1fead6373d54f05d55b0a74862bbf68de397e4) | 2145250021 |
| [LOOPERSPLUS_aR7#Wm9@Tq](https://www.virustotal.com/gui/file/41583cc1f18c2dd3dd5295925eb96d355727966de34b97c6c044a8072a987393) | 124576116 |

In rare [cases](https://www.virustotal.com/gui/file/65fe798ef89a8b019556b2cf87301355a97bb68aa9e1d9cfda42a8dd09b55e3a), simply an initial seed can't fully reproduce the shuffle. We don't know why.
