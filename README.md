# SiglusSceneScriptUtility

This utility aims to reproduce **SiglusEngine** SceneScript compilation as exactly as possible, along with other related (and unrelated) features.

## Installation

### Option 1: Install from PyPI

```bash
pip install siglus-ssu
```

After installing from PyPI, you **must** run `init` once to download the required `const.py` at runtime:

```bash
siglus-ssu init
```

### Option 2: Install from source

#### 1. Install `uv`

This project uses [uv](https://github.com/astral-sh/uv) for project management.

#### 2. Install Rust toolchain

You need to install a Rust compiler if you want the acceleration provided by the Rust native extension. Visit [rustup.rs](https://rustup.rs/) and follow the instructions for your platform.

#### 3. Set up the project

Run the following command in the project root to build the Rust extension and sync dependencies:

```bash
uv sync
```

## Features

1. Compilation of `.pck` files.
2. Analysis and extraction of `.pck`, `.dat`, `.dbs`, `.gan`, `.sav`, `.cgm`, `.tcr`, `.g00`, `.nwa`, `.ovk`, `.owp`, `.omv` files.
3. Disassemble `.dat` files.
4. Textmapping for translators.
5. Koe collector by character names.

## Usage

If you installed via PyPI, you can run the command directly:

```bash
siglus-ssu --help
```

If you are running from source with uv, prefix commands with `uv run`:

```bash
uv run siglus-ssu --help
```

### Examples for a translator

Extract a given `Scene.pck` to a `translation_work` folder:

```bash
siglus-ssu -x /path/to/Scene.pck /path/to/translation_work
```

After editing some `.ss` files, compile them back into a `Scene_translated.pck`:

```bash
siglus-ssu -c /path/to/translation_work /path/to/Scene_translated.pck
```

## Tips

- If you type something in a `.ss` file that would break tokenization, wrap it in double quotes so it's treated as a literal.
- Some official builds shuffled their strings with a magical initial seed. If you want to reproduce the shuffle bit-by-bit (you don't have to, though—it won't affect your engine's parsing), set the initial seed with `--set-shuffle`.
  - If you don't know the seed, try to find it with `--test-shuffle`, which is expected but not guaranteed to be there.
  - In rare cases, a single initial seed can't fully reproduce the shuffle. My guess is that this is a result of incremental compilation (we have this too, via the `--tmp` option), which makes the file order different.
- There is no prebuilt wheel for Termux, so you may need to build the Rust extension by yourself, which is not easy.

## TODOs

1. Support element list for Flix builds.
2. GUI or WebUI supports.
