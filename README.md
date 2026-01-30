# SiglusSceneScriptUtility

This utility aims to reproduce compilation of SceneScripts of SiglusEngine as exactly as possible, along with other related (and unrelated) features.

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
You need to install Rust compiler if you need the acceleration by the Rust native extension. Visit [rustup.rs](https://rustup.rs/) and follow the instructions for your platform.

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

### Examples for a translator

Extract a given `Scene.pck` to `translation_work` folder.
```bash
uv run siglus-ssu -x /path/to/Scene.pck /path/to/translation_work
```

After editing some `.ss` files, you may want to compile them back to a `Scene_translated.pck`.
```bash
uv run siglus-ssu -c /path/to/translation_work /path/to/Scene_translated.pck
```

You can set a fixed tmp folder so that `siglus-ssu` only recompiles changed files (works after `_md5.json` is created),
```bash
uv run siglus-ssu -c /path/to/translation_work /path/to/Scene_translated.pck --tmp /path/to/tmp
```
and run the game with a specified scene and z-label to see how your translation looks z-label-by-z-label.
```bash
uv run siglus-ssu -e /path/to/SiglusEngine.exe scene_name z-label
```


## Tips

If you type something in a `.ss` file that would break tokenization, wrap it in double quotes so it's treated as a literal.

Some official builds shuffled their strings with a magical initial seed. If you want to reproduce the shuffle bit-by-bit (you don't have to, though. It won't affect your engine's parsing), set the initial seed with --set-shuffle. If you don't know the seed, try to find it with --test-shuffle, which is expected but not guaranteed to be there. In rare cases, simply an initial seed can't fully reproduce the shuffle. My guess for the reason of this is that it's a result of incremental compilation (we have this, too, the --tmp option), which made the file order different.

