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

## Benchmarks

Run the benchmark script to see the speed improvement on your machine:
```bash
uv run python tests/benchmark.py
```
