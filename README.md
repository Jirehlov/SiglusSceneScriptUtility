# SiglusSceneScriptUtility

This utility can compile and extract SiglusEngine scene scripts and data. It features **Rust-accelerated core operations** (LZSS, MD5, XOR) for significantly improved performance.

## Performance Note

The original Python LZSS implementation was very slow. This project now includes a Rust native extension that provides up to **50x speedup** for LZSS and **180x speedup** for MD5.

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

# Compile scripts
uv run siglus-ssu -c <input_dir> <output_dir>

# Extract PCK files
uv run siglus-ssu -x <input_pck> <output_dir>

# Analyze or compare files
uv run siglus-ssu -a <file1> [file2]
```

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
