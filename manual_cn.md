# SiglusSceneScriptUtility 使用手册

**版本：** 见 `siglus-ssu --version`
**仓库：** https://github.com/Jirehlov/SiglusSceneScriptUtility
**英文版：** [manual.md](manual.md)

---

## 目录

1. [概述](#概述)
2. [安装](#安装)
   - [方式一：从 PyPI 安装](#方式一从-pypi-安装)
   - [方式二：从源码安装](#方式二从源码安装)
3. [基本用法](#基本用法)
   - [全局选项](#全局选项)
   - [命令别名](#命令别名)
   - [获取帮助](#获取帮助)
4. [模式参考](#模式参考)
   - [init — 下载运行时常量](#init--下载运行时常量)
   - [-lsp — 启动语言服务器](#-lsp--启动语言服务器)
   - [-c / --compile — 编译脚本](#-c----compile--编译脚本)
   - [-x / --extract — 提取文件](#-x----extract--提取文件)
   - [-a / --analyze — 分析和比较文件](#-a----analyze--分析和比较文件)
   - [-d / --db — 导出和编译 `.dbs` 数据库](#-d----db--导出和编译-dbs-数据库)
   - [-k / --koe — 按角色收集语音文件](#-k----koe--按角色收集语音文件)
   - [-e / --exec / --execute — 从指定标签启动引擎](#-e----exec----execute--从指定标签启动引擎)
   - [-m / --textmap — 翻译用文本映射](#-m----textmap--翻译用文本映射)
   - [-g / --g00 — 处理 `.g00` 图片文件](#-g----g00--处理-g00-图片文件)
   - [-s / --sound — 处理音频文件](#-s----sound--处理音频文件)
   - [-v / --video — 处理 `.omv` 视频文件](#-v----video--处理-omv-视频文件)
   - [-p / --patch — 修改 `SiglusEngine.exe`](#-p----patch--修改-siglusengineexe)
5. [SiglusSceneScript语言规范（简称 SiglusSS语言；以 -c 编译器为定义）](#siglusss-language-spec)
6. [提示与故障排除](#提示与故障排除)

---

## 概述

**SiglusSceneScriptUtility**（缩写 **SSSU**，命令名 **siglus-ssu**）是用于操作 **SiglusEngine** 视觉小说引擎所使用文件的命令行工具。它精确复现了引擎的 SceneScript 编译流程，并提供了一套完整的工具集：

- 提取和重新编译 `.pck` 场景文件
- 分析二进制格式（`.dat`、`.dbs`、`.gan`、`.sav`、`.cgm`、`.tcr`）
- 反汇编 `.dat` 编译脚本
- 为翻译工作导出和应用文本映射
- 从 `.ovk` 文件按角色收集语音音频
- 提取和重新编译 `.g00` 图片文件
- 解码和重新编码 `.nwa` / `.owp` / `.ovk` 音频文件
- 提取和重新编译 `.omv` 视频文件
- 为 `SiglusEngine.exe` 打补丁（修改密钥或语言设置）
- 提供SiglusSS语言的LSP

> **兼容性提醒：** 本项目不支持版本过低的 **SiglusEngine** 所使用的相关资源文件。如果某个游戏使用了非常老的引擎版本，则其部分资源格式或常量定义可能与当前支持范围不一致，本手册中的工具和流程可能无法正常工作。

---

## 安装

### 方式一：从 PyPI 安装

```bash
pip install siglus-ssu
```

安装后，**必须**运行一次 `init` 以下载运行时所需的 `const.py`：

```bash
siglus-ssu init
```

> **注意：** 需要 Python 3.12 或更高版本。软件包内置了预编译的 Rust 原生扩展以加速关键操作。如果您的平台没有预构建的 wheel（例如 Android 上的 Termux），则需要自行从源码构建 Rust 扩展。
>
> `const.py` 存储在平台特定的用户数据目录：
> - **Windows：** `%APPDATA%\siglus-ssu\const.py`
> - **Unix/Linux/macOS：** `~/.local/share/siglus-ssu/const.py`（或 `$XDG_DATA_HOME/siglus-ssu/const.py`）

### 方式二：从源码安装

#### 前提条件

- **Python 3.12+**
- **uv** — 项目管理器（[安装指南](https://github.com/astral-sh/uv)）
- **Rust 工具链** — 构建原生扩展所需（[rustup.rs](https://rustup.rs/)）

#### 步骤

1. 克隆仓库。
2. 在项目根目录运行：

   ```bash
   uv sync
   ```

   这将构建 Rust 扩展并将所有依赖安装到本地虚拟环境中。

3. 所有命令前加 `uv run` 前缀：

   ```bash
   uv run siglus-ssu --help
   ```

   若这台机器的用户数据目录里还没有通过校验的 `const.py`，那么在运行除 `init` 以外的模式前，仍需先执行一次：

   ```bash
   uv run siglus-ssu init
   ```

---

## 基本用法

```
siglus-ssu [-h] [-V | --version] [--legacy] [--const-profile N] (-lsp | init | -c | -x | -a | -d | -k | -e | -m | -g | -s | -v | -p) [参数]
```

### 全局选项

| 选项 | 说明 |
|---|---|
| `-h`, `--help` | 显示帮助信息并退出。 |
| `-V`, `--version` | 显示程序版本并退出。 |
| `--legacy` | 禁用 Rust 原生加速，使用纯 Python 回退实现。可用于调试。 |
| `--const-profile N` | 选择内置的 `const.py` profile（`0`-`2`，默认 `0`）。只有在目标引擎或编译器变体的 form / element 表与默认 profile 不一致时，才需要改用非默认 profile。 |

### 命令别名

CLI 也接受几个便利用法：

- `siglus-ssu help` 等同于 `siglus-ssu --help`
- `siglus-ssu version` 等同于 `siglus-ssu --version`
- `siglus-ssu --init ...` 等同于 `siglus-ssu init ...`

### 获取帮助

```bash
# 显示全局帮助，列出所有模式
siglus-ssu --help

# LSP 模式有独立帮助页
siglus-ssu -lsp --help

# 除 LSP 外，当前 CLI 其他模式仍没有独立的模式级帮助页；下面的写法仍会显示全局帮助
siglus-ssu -c --help
```

---

## 模式参考

### `init` — 下载运行时常量

从项目 GitHub 仓库下载 `const.py` 文件，其中包含引擎特定的常量（操作码表、密钥推导参数等）。

**每次在一台新机器上首次使用前，都必须先确保用户数据目录中存在已校验的 `const.py`。对从 PyPI 安装的用户，这通常意味着先运行一次 `init`；即使是从源码运行，只要该用户目录里还没有有效的 `const.py`，也仍然需要先执行 `init`。**

#### 语法

```
siglus-ssu init [--force | -f] [--ref <git-ref>]
```

#### 参数

| 参数 | 说明 |
|---|---|
| `--force`, `-f` | 即使已存在 `const.py` 也强制覆盖。 |
| `--ref <git-ref>` | 从指定的 Git 分支、标签或提交哈希下载 `const.py`。默认会优先尝试当前包版本对应的发布 ref，再尝试匹配的标签名。 |

`init` 需要联网访问 GitHub API。若未加 `--force` 且目标位置已经存在 `const.py`，命令不会重新下载，而是直接加载并校验现有文件。

下载完成后，`const.py` 会与内置的 SHA-512 白名单进行校验。内置的默认 ref 映射现在只跟踪当前支持的包版本；显式传入的 `--ref` 只要最终解析到同一份白名单内的 `const.py` 内容，仍然可以使用。

#### 示例

```bash
# 基本初始化（下载与当前包版本对应的 const.py）
siglus-ssu init

# 覆盖已有的 const.py
siglus-ssu init --force

# 从特定标签下载
siglus-ssu init --ref v0.2.1
```

---

### `-lsp` — 启动语言服务器

启动面向 **SiglusSceneScript语言**（简称 **SiglusSS语言**）以及 `.inc` 声明文件的标准 **stdio JSON-RPC / Language Server Protocol** 服务。

#### 语法

```
siglus-ssu -lsp
```

#### 参数

无。

#### 说明

- 官方启动入口：`siglus-ssu -lsp`
- 当前能力：语义 token、诊断、自动补全、悬停说明、跳转到定义、查找引用、准备改名、改名、文档符号，以及同目录未保存 `.inc` 缓冲区对 `.ss` 分析结果的联动刷新；当前语义 token 分类包含台词文本、system element（系统指令）和角色名
- 语言服务会在适用处直接复用与 `-c` 相同的编译流水线阶段（`CA`、`LA`、`SA`、`MA`、`BS`）；语义分类来自这条与编译器对齐的分析结果，而 LSP 层负责恢复源文本范围，并把结果封装成 semantic token、location 与 edit
- 当前项目作用域是目录级的，这与现行 `-c` 对 `.inc` / `.ss` 联合分析以及全局 `.inc #command` 链接的模型保持一致
- 服务本身与编辑器无关，可供 VS Code、Neovim、Emacs、Sublime Text、Kate、Helix 等任何支持外部 stdio LSP 的客户端接入
- 推荐的编辑器组织方式是：编辑器扩展负责兜底词法 grammar、命令、任务与 UI；语义高亮、lint、导航、引用与改名则委托给 `siglus-ssu -lsp`

---

### `-c` / `--compile` — 编译脚本

将一个目录中的 `.ss` SceneScript 源文件编译为 `.pck` 文件。编译过程中会先在临时目录生成各个场景的 `.dat`，然后在常规模式下再将它们链接并打包为最终的 `Scene.pck`。编译流程精确复现官方 SiglusEngine 构建系统，包括 LZSS 压缩、每脚本字符串表乱序、以及基于 `暗号.dat` 的加密。

也支持通过 `--gei` 单独编译 `Gameexe.ini` → `Gameexe.dat`。

#### 语法

```
# 标准编译
siglus-ssu -c [选项] <input_dir> <output_pck | output_dir>

# 仅从现有 Gameexe.ini 编译 Gameexe.dat
siglus-ssu -c --gei <input_dir | Gameexe.ini> <output_dir>

# 编译并穷举搜索混淆种子
siglus-ssu -c --test-shuffle [seed0] <input_dir> <output_pck | output_dir> <test_dir>
```

#### 参数

| 参数 | 说明 |
|---|---|
| `<input_dir>` | 包含 `.ss` 源文件的目录，可选包含 `.inc`、`.ini` / `Gameexe.ini`、`暗号.dat`。 |
| `<output_pck \| output_dir>` | 输出路径。若以 `.pck` 结尾，则写入该文件；若参数本身已存在且是目录，或以路径分隔符结尾，则在其中创建 `Scene.pck`。其余不存在且不以 `.pck` 结尾的路径，当前实现也会按“输出文件路径”解释。 |
| `--debug` | 编译后保留中间临时文件（`.dat`、`.lzss` 等），并打印各阶段耗时统计。 |
| `--charset ENC` | 强制指定源文件编码。接受值：`jis`、`cp932`、`sjis`、`shift_jis`（均等价于 Shift-JIS）或 `utf8`、`utf-8`。省略时自动检测。 |
| `--no-os` | 跳过 OS（原始 source）嵌入阶段。仍会正常生成并写出 `Scene.pck`，只是包内不再附带原始 source；不影响脚本本身的加密或压缩。 |
| `--dat-repack` | 不编译 `.ss` 脚本，而是扫描 `input_dir` 中现有的 `.dat` 文件并将它们直接打包成一个 `.pck` 文件。这对于打包已经编译好的脚本非常有用。它只能与 `--no-os` 和/或 `--no-lzss` 组合使用。不能与 `--test-shuffle` 同用。 |
| `--no-angou` | 禁用 LZSS 压缩和 XOR 加密（`header_size=0`）。可用于调试或无加密的引擎。 |
| `--no-lzss` | 仅禁用 LZSS 阶段，同时保留脚本原有的加密与头部行为。这对应官方的“easy link”式输出。 |
| `--parallel` | 启用多进程并行编译以加速大型项目。 |
| `--max-workers N` | 最大并行工作进程数。仅在 `--parallel` 下生效；默认为自动。 |
| `--lzss-level N` | LZSS 压缩级别，`2`（快，文件大）到 `17`（慢，文件最小）。默认：`17`。 |
| `--set-shuffle SEED` | 设置每脚本字符串表位置混淆的 MSVC 兼容 `rand()` 初始种子。接受十进制或 `0x...` 十六进制。默认：`1`。 |
| `--tmp <tmp_dir>` | 使用指定的持久临时目录。提供此参数后，编译器会在该目录内维护 MD5 缓存（`_md5.json`），从而实现**增量编译**——后续运行时只重编译已更改的 `.ss` 文件。 |
| `--test-shuffle [seed0]` | 穷举搜索所有可能的 32 位 MSVC `rand()` 种子，以找到能精确重建 `<test_dir>` 中字符串表混淆顺序的种子。可选从 `seed0` 开始扫描。 |
| `--gei` | 仅运行 `Gameexe.ini` → `Gameexe.dat` 编译阶段，并在输出目录写出固定文件名 `Gameexe.dat`。 |

#### 示例

```bash
# 将翻译目录编译为新的 Scene.pck
siglus-ssu -c /path/to/translation_work /path/to/Scene_translated.pck

# 并行编译，保留临时文件供检查
siglus-ssu -c --parallel --debug /path/to/src /path/to/out/

# 增量编译：只重编译已更改的 .ss 文件
siglus-ssu -c --tmp /path/to/cache /path/to/src /path/to/Scene.pck

# 使用指定乱序种子编译（逐字节匹配官方输出）
siglus-ssu -c --set-shuffle 12345 /path/to/src /path/to/Scene.pck

# 从 12345 开始穷举搜索混淆种子
siglus-ssu -c --test-shuffle 12345 /path/to/src /path/to/out/ /path/to/original_dats/

# 将现有 .dat 文件直接重新打包
siglus-ssu -c --dat-repack /path/to/dat_dir /path/to/Scene_repacked.pck

# 将现有 .dat 文件直接重新打包，并且不做 LZSS
siglus-ssu -c --dat-repack --no-lzss /path/to/dat_dir /path/to/Scene_repacked.pck

# 仅生成 Gameexe.dat
siglus-ssu -c --gei /path/to/src /path/to/out/

# 强制 UTF-8 编码并禁用加密
siglus-ssu -c --charset utf8 --no-angou /path/to/src /path/to/out/
```

#### 说明

- **自动编码检测：** 若未指定 `--charset`，工具会扫描 `.ss`、`.inc`、`.ini` 文件中的 UTF-8 BOM 或日文字符。找到则使用 `utf-8`，否则使用 `cp932`（Shift-JIS）。
- **增量编译：** 当指定 `--tmp` 时，编译器会缓存所有 `.ss` 和 `.inc` 文件的 MD5 哈希。下次运行时仅重编译已更改（或缺少对应 `.dat`）的文件。若任一 `.inc` 文件发生变化，则触发全量重编译。
- **字符串混淆：** 本工具支持用 MSVC 兼容 `rand()` 种子复现每个 `.dat` 的字符串表位置乱序。翻译工作通常**不需要**复现这一点；`--set-shuffle` 和 `--test-shuffle` 主要用于追求逐字节一致的二进制输出。

---

### `-x` / `--extract` — 提取文件

将 `.pck` 场景文件提取为一个带时间戳的目录，目录内包含已解码的场景 `.dat` 文件以及包内嵌入的原始 source 文件；或者从二进制 `Gameexe.dat` 还原 `Gameexe.ini` 明文。

#### 语法

```bash
# 提取 .pck 文件
siglus-ssu -x [--disam] <input_pck> [output_dir]

# 对目录中的 `.dat` 批量反汇编并反编译
siglus-ssu -x --disam <input_dir> [output_dir]

# 从 Gameexe.dat 还原 Gameexe.ini
siglus-ssu -x --gei <Gameexe.dat | input_dir> [output_dir]
```

#### 参数

| 参数 | 说明 |
|---|---|
| `<input_pck>` | 要提取的 `.pck` 文件路径。 |
| `<input_dir>` | 启用 `--disam` 时，用来扫描 `.dat` 的目录路径。只处理该目录当前层的 `.dat` 文件。 |
| `<output_dir>` | 提取文件的输出目录。对所有 `-x` 模式都可省略；省略时默认输出到输入文件所在目录，若输入本身是目录，则默认输出到该目录。 |
| `--disam` | 对 `.pck` 输入时，除写出 `<scene>.dat.txt` 反汇编外，还会额外写出重建后的 `decompiled/<scene>.ss` 以及 `decompiled/__decompiled.inc`。对目录输入时，只扫描该目录当前层的 `.dat`，并将 `.dat.txt` 和 `decompiled/*.ss` 写入 `<output_dir>`。不能与 `--gei` 同用。非场景 `.dat` 会自动跳过。 |
| `--gei` | 不提取 `.pck`，而是将 `Gameexe.dat` 二进制文件解码还原为 `Gameexe.ini` 明文文件。输入参数可以是 `.dat` 文件本身或其父目录。会尝试自动检测可用的 `暗号.dat`、`key.txt` 或 `SiglusEngine*.exe` 以推导解密密钥。 |

对 `.pck` 输入时，实际输出会写入 `output_YYYYMMDD_HHMMSS/` 目录。若包内存在原始 source，会与解码后的场景 `.dat` 一起还原出来。启用 `--disam` 时，命令结束前还会打印反汇编、hints 和反编译三个阶段的总耗时。

当前 decompiler 属于实验性质。`decompiled/*.ss` 更适合拿来阅读和排查，不应视为对原始 source 的可靠还原，也不应默认当作稳定可回编的发布输入。

#### 示例

```bash
# 将 Scene.pck 提取到 translation_work 目录
siglus-ssu -x /path/to/Scene.pck /path/to/translation_work/

# 将 Scene.pck 提取到输入文件同目录
siglus-ssu -x /path/to/Scene.pck

# 提取并附带 `.dat` 反汇编和反编译 `.ss`
siglus-ssu -x --disam /path/to/Scene.pck /path/to/translation_work/

# 对单个目录当前层的 `.dat` 批量反汇编并反编译
siglus-ssu -x --disam /path/to/scene_dir/

# 从 Gameexe.dat 还原 Gameexe.ini
siglus-ssu -x --gei /path/to/Gameexe.dat /path/to/output/
```

---

### `-a` / `--analyze` — 分析和比较文件

分析支持的二进制文件的内部结构，并将详细报告打印到标准输出。提供两个同类型文件时，执行结构比较。

#### 支持的文件类型

`.pck`、`.dat`、`.gan`、`.sav`、`.cgm`、`.tcr`

#### 语法

```
# 分析单个文件
siglus-ssu -a [--disam] [--readall] [--payload] <input_file>

# 仅统计 .pck 中的台词计数并导出逐文件 CSV
siglus-ssu -a --word <input_pck> [output_csv]

# 比较两个同类型文件
siglus-ssu -a [--payload] <input_file_1> <input_file_2>

# 从 暗号.dat / SiglusEngine.exe / 目录 分析或推导 exe_el 密钥
siglus-ssu -a <暗号.dat路径 | SiglusEngine.exe路径 | 目录> --angou

# 分析或比较 Gameexe.dat
siglus-ssu -a --gei <Gameexe.dat> [Gameexe.dat_2]
```

#### 参数

| 参数 | 说明 |
|---|---|
| `<input_file>` | 要分析的文件路径。支持扩展名：`.pck`、`.dat`、`.gan`、`.sav`、`.cgm`、`.tcr`。 |
| `[input_file_2]` | 用于比较的可选第二个文件。若两个文件类型相同，则执行结构比较；若类型不同，则退化为分别分析两个文件。 |
| `--disam` | 分析 `.dat` 文件时，将可读反汇编写在输入 `.dat` 同目录下的 `<scene>.dat.txt`，并额外输出重建后的 `decompiled/*.ss` 与 `decompiled/__decompiled.inc`。命令结束前会打印反汇编、hints 和反编译三个阶段的总耗时。decompiler 输出目前仍属实验性质，不应视为可靠真值。 |
| `--readall` | 仅用于 `read.sav` 文件：将所有已读标志位设为 `1`（标记所有场景为已读）。直接覆盖输入文件。 |
| `--word` | 仅用于 `.pck`：跳过常规结构分析，统计每个已解码场景 `.dat` 和每个内嵌 `.ss` source 的台词计数，逐文件打印，并写入 CSV。若省略 `[output_csv]`，则默认写到输入 `.pck` 同目录下的 `<input_pck_stem>.word.csv`。 |
| `--payload` | 对 `.pck` 和 `.dat` 的比较额外执行“规范化后的解码/解压 `scn_bytes` 语义”比较。当解析出的文本相同而仅有字符串池 `str_id` 不同时，会视为相同；但文本变化和其他场景字节码变化仍会视为不同。它比普通结构比较更耗时，但能更好地区分场景内容变化与容器层面的差异。 |
| `--angou` | 将输入解析为 `暗号.dat`（或 `SiglusEngine*.exe`、或包含两者之一的目录），推导并打印 `exe_el` 密钥（`key.txt` 格式的 16 字节密钥）。 |
| `--gei` | 分析或比较 `Gameexe.dat` 文件，而非通用二进制文件。 |

#### 示例

```bash
# 分析 Scene.pck — 打印头部信息、文件数量、加密状态
siglus-ssu -a /path/to/Scene.pck

# 统计每个场景 `.dat` 与内嵌 `.ss` 的台词计数，并写出 CSV
siglus-ssu -a --word /path/to/Scene.pck

# 统计台词计数，并把 CSV 写到指定路径
siglus-ssu -a --word /path/to/Scene.pck /path/to/scene_counts.csv

# 分析编译后的 .dat 脚本 — 打印头部字段和字符串池
siglus-ssu -a /path/to/script.dat

# 比较两个版本的 Scene.pck — 报告文件增删和变化
siglus-ssu -a /path/to/Scene_original.pck /path/to/Scene_translated.pck

# 比较两个 Scene.pck 的规范化解码 `scn_bytes` 语义
siglus-ssu -a --payload /path/to/Scene_original.pck /path/to/Scene_translated.pck

# 将 .dat 反汇编写入磁盘以供检查
siglus-ssu -a --disam /path/to/script.dat

# 将 read.sav 中的所有已读标志设为 1
siglus-ssu -a --readall /path/to/savedata/read.sav

# 从 暗号.dat 推导 exe_el 密钥
siglus-ssu -a /path/to/暗号.dat --angou

# 直接从 SiglusEngine 可执行文件推导 exe_el 密钥
siglus-ssu -a /path/to/SiglusEngine.exe --angou

# 从游戏目录推导 exe_el 密钥（自动检测 暗号.dat 或 exe）
siglus-ssu -a /path/to/game_dir/ --angou
```

#### 输出格式（`.pck` 示例）

```
==== Analyze ====
file: /path/to/Scene.pck
type: pck
size: 123456789 bytes (0x75BCD15)
mtime: 2024-01-01 12:00:00
sha1: a1b2c3d4...

header:
  header_size=...
  scn_data_exe_angou_mod=...
  original_source_header_size=...
counts:
  inc_prop=...  inc_cmd=...
  scn_name=...  scn_data_index=...  scn_data_cnt=...
...
```

如果能从 `.pck` 内嵌 original source 或输入 `.pck` 同目录找到 `暗号.dat`，`.pck` 分析还会在末尾追加一个 `=== 暗号.dat ===` 区块，并打印它的第一行，风格与编译模式的汇总输出一致。


#### 字数统计输出（`-a --word`）

`-a --word` 会为每个已解码场景 `.dat` 和每个内嵌 `.ss` source 打印一行，并写出同内容的 CSV。计数规则如下：

- 汉字、平假名、片假名、注音符号每个字符算 `1`
- 韩文按连续词段计数
- 其他字母和数字按连续词段计数
- 非亚洲词段中，内部的 `'`、`’`、`-`、`_` 在两侧都是字母数字时不拆分
- 数字段中，内部的 `.`, `,`, `/`, `:` 在两侧都是十进制数字时不拆分
- 标点、空白、emoji 以及其他符号算 `0`

CSV 列为：

- `type` — `dat` 或 `ss`
- `path` — `.pck` 内的逐文件相对路径
- `status` — `ok` 或 `failed`
- `dialogue_lines` — 计入统计的台词条目数
- `dialogue_count` — 计入统计的台词总计数

---

### `-d` / `--db` — 导出和编译 `.dbs` 数据库

处理 `.dbs` 二进制数据库文件，这些文件以表格形式（行和列）存储引擎用于配置、场景流程或其他结构化数据的内容。

提供三个子操作，通过 `--x`、`--a` 或 `--c` 选择。

#### 语法

```
# 导出一个或多个 .dbs 文件到 CSV
siglus-ssu -d --x <input_dir | input_file.dbs> <output_dir>

# 分析 .dbs 文件（或比较两个）
siglus-ssu -d --a <input_file.dbs> [input_file_2.dbs]

# 将 CSV 编译回 .dbs
siglus-ssu -d --c [--type N] [--set-shuffle SEED] <input_csv | input_dir> <output_dbs | output_dir>

# 暴力破解 MSVC rand() 跳过量以匹配参考 .dbs
siglus-ssu -d --c --test-shuffle [skip0] <expected.dbs> <input.csv> <output.dbs | output_dir>
```

#### 参数

| 参数 | 说明 |
|---|---|
| `--x` | **提取**模式：导出 `.dbs` → `.csv`。 |
| `--a` | **分析**模式：转储结构信息。提供两个参数时比较两个 `.dbs` 文件。 |
| `--c` | **编译**模式：从 `.csv` 创建 `.dbs`。 |
| `--type N` | 覆盖生成的 `.dbs` 的 `m_type` 字段（整数）。默认：`1`。 |
| `--set-shuffle SEED` | 设置内部字符串顺序的 MSVC `rand()` 初始种子。接受十进制或 `0x...` 十六进制。默认：`1`。 |
| `--test-shuffle [skip0]` | 暴力破解匹配参考 `.dbs` 文件末尾附加填充模式（Padding Pattern）所需的 MSVC `rand()` 跳过量。可选从 `skip0` 开始。仅支持单文件模式。 |

#### 示例

```bash
# 将目录中所有 .dbs 文件导出为 CSV
siglus-ssu -d --x /path/to/dbs_dir/ /path/to/csv_out/

# 导出单个 .dbs 文件
siglus-ssu -d --x /path/to/gamedb.dbs /path/to/csv_out/

# 分析 .dbs 文件
siglus-ssu -d --a /path/to/gamedb.dbs

# 比较两个 .dbs 文件
siglus-ssu -d --a /path/to/gamedb_original.dbs /path/to/gamedb_translated.dbs

# 将单个 CSV 编译回 .dbs
siglus-ssu -d --c /path/to/gamedb.dbs.csv /path/to/gamedb_translated.dbs

# 将一个目录的 CSV 批量编译为 .dbs
siglus-ssu -d --c /path/to/csv_dir/ /path/to/dbs_out/

# 指定乱序种子和类型编译
siglus-ssu -d --c --type 2 --set-shuffle 12345 /path/to/gamedb.dbs.csv /path/to/out.dbs

# 穷举搜索 MSVC rand() 跳过量以精确匹配参考 .dbs
siglus-ssu -d --c --test-shuffle /path/to/original.dbs /path/to/input.csv /path/to/output.dbs
```

目录输入时，`-d --x` 与 `-d --c` 都会**递归**扫描子目录，并在输出端保留相对目录结构。

#### CSV 格式

导出的 CSV 使用带 BOM 的 UTF-8 编码和 CRLF 换行，与 Microsoft Excel 兼容。文件前两行为 `#DATANO` 和 `#DATATYPE` 头行，之后才是数据行。

- `#DATANO` 行：首列固定为 `#DATANO`，其余各列是列头的 call number。
- `#DATATYPE` 行：首列固定为 `#DATATYPE`，其余各列是对应列的数据类型标记；当前主要会看到 `S`（字符串）和 `V`（数值/其他 32 位单元）。
- 数据行：每行首列是该行的 row call number，其余各列按前两行定义的列顺序对应。

字符串值中的特殊字符经过转义：

| 转义序列 | 含义 |
|---|---|
| `\\` | 字面反斜杠 |
| `\n` | 换行 |
| `\r` | 回车 |
| `\t` | 制表符 |

---

### `-k` / `--koe` — 按角色收集语音文件

扫描 `.pck`、单个场景 `.dat`，或场景 `.dat` 目录树中的编译后场景数据，从反汇编 trace 中读取 KOE 相关调用，将其与 `.ovk` 语音文件条目匹配，并提取对应的 `.ogg` 音频文件。普通模式下，输出会按角色名分类到子目录中。

普通模式下还会生成 `koe_master.csv` 清单，列出所有找到的 KOE 条目及其角色名、对话文本和调用位置。若直接扫描 `.pck`，调用位置会写成 `Scene.pck!scene.dat:line`。命令处理完成后还会统计**已引用语音**的总时长；写入 `unreferenced/` 的条目不会计入该总时长。若某个 `.ogg` 的时长读取失败，也不会阻止 CSV 导出，但会计入 `Duration failed` 统计。

#### 语法

```
siglus-ssu -k [--stats-only] <scene_input> <voice_dir> <output_dir>
siglus-ssu -k [--stats-only] --single KOE_NO <voice_dir> <output_dir>
```

#### 参数

| 参数 | 说明 |
|---|---|
| `<scene_input>` | `Scene.pck`、单个场景 `.dat` 文件，或场景 `.dat` 目录树的路径。普通模式必填；使用 `--single` 时不需要。 |
| `<voice_dir>` | 包含 `.ovk` 语音文件的目录（通常命名为 `z0001.ovk`、`z0002.ovk` 等）。也可以是单个 `.ovk` 文件的路径。目录模式当前只扫描该目录当前层的 `.ovk` 文件，不递归。 |
| `<output_dir>` | 提取的 `.ogg` 文件输出目录。普通模式下还会在这里写出 `koe_master.csv`；使用 `--single` 时，提取出的单个文件会直接写到 `<output_dir>` 根下。 |
| `--stats-only` | 打印汇总，但不会写任何 `.ogg` 文件。普通模式下仍会写出 `koe_master.csv`；若同时使用 `--single`，则不会写 CSV。 |
| `--single KOE_NO` | 仅提取指定的全局 KOE 编号。此模式下不需要场景输入，不会生成 `koe_master.csv`，不会创建角色名或 `unreferenced` 子目录，输出文件会直接写成 `<output_dir>/KOE(XXXXXXXXX).ogg`。 |

#### 输出结构

```
<output_dir>/
  koe_master.csv           — 所有 KOE 条目的主清单
  <角色名或 unknown>/     — 每个角色一个子目录；无法推断角色名时使用 unknown
    KOE(000000001).ogg
    KOE(000000002).ogg
    ...
  unreferenced/            — .ovk 中未被任何已扫描场景引用的条目
    KOE(000000003).ogg
    ...
```

使用 `--single` 时，输出结构变为：

```
<output_dir>/
  KOE(123456789).ogg
```

#### 示例

```bash
# 直接从 Scene.pck 收集所有语音文件
siglus-ssu -k /path/to/Scene.pck /path/to/voice/ /path/to/voice_out/

# 从解码后的场景 `.dat` 目录收集
siglus-ssu -k /path/to/scene_dir/ /path/to/voice/ /path/to/voice_out/

# 从单个场景 `.dat` 文件收集（用于测试）
siglus-ssu -k /path/to/chapter1.dat /path/to/voice/ /path/to/voice_out/

# 只生成 CSV 和汇总，不写任何 `.ogg`
siglus-ssu -k --stats-only /path/to/Scene.pck /path/to/voice/ /path/to/voice_out/

# 只提取一个全局 KOE 条目
siglus-ssu -k --single 123456789 /path/to/voice/ /path/to/voice_out/
```

#### `koe_master.csv` 格式（仅普通模式）

| 列名 | 说明 |
|---|---|
| `koe_no` | 全局 KOE 编号（场景号 × 100000 + 条目号）。对于未在 OVK 中找到的调用，这一列为空。 |
| `character` | 从 scene trace 中的 `CD_NAME` 事件和行内语音元数据推断出的角色名。 |
| `text` | 从 scene trace 中的 `CD_TEXT` 事件和行内语音元数据推断出的文本。 |
| `callsite` | 分号分隔的 `文件名:行号` 调用位置列表；若直接扫描 `.pck`，则为 `Scene.pck!scene.dat:line`。 |

#### 完成后汇总输出（stderr）

```
=== koe_collector summary ===
Stats only       : yes
Single KOE       : 123456789
OVK entries      : 45,678
OVK files        : 56
OVK z-files      : 56
OVK table errors : 0
Scene files      : 128
Scene callsites  : 44,210
Scene missing    : 124
KOE total        : 45,678
KOE referenced   : 44,086
KOE unreferenced : 1,592
Audio extracted  : 43,900
Audio skipped    : 186
Audio failed     : 0
Voice duration   : 123,456.789 sec (34:17:36.789) [referenced only]
Duration counted : 44,086
Duration failed  : 0
CSV path         : /path/to/voice_out/koe_master.csv
CSV rows         : 45,724
Out dir          : /path/to/voice_out/
```

上面的示例是普通模式输出。`Stats only` 和 `Single KOE` 仅在使用对应选项时出现。使用 `--single` 时，不会显示场景扫描相关行，也不会显示 CSV 相关行。

---

### `-e` / `--exec` / `--execute` — 从指定标签启动引擎

直接将 `SiglusEngine.exe` 启动到指定场景和 `#z` 标签处。适用于测试时快速跳转到特定场景，无需从头重玩游戏。

#### 语法

```
siglus-ssu -e <path_to_engine> <scene_name> <label>
```

#### 参数

| 参数 | 说明 |
|---|---|
| `<path_to_engine>` | `SiglusEngine.exe` 的绝对或相对路径。引号会自动去除。 |
| `<scene_name>` | 不含目录的脚本名（如 `opening` 或 `opening.ss`）。必须是不含路径分量的纯文件名。 |
| `<label>` | 要跳转到的 `#z` 标签编号。`#z` 前缀可省略——`10`、`z10`、`#z10` 均可接受。 |

#### 工作原理

工具在引擎可执行文件旁边创建一个日期命名的工作目录 `work_YYYYMMDD`，并以如下参数启动它：

```
SiglusEngine.exe /work_dir=<work_dir> /start=<scene_name> /z_no=<label> /end_start
```

引擎作为独立子进程启动，工具在启动后立即返回。

#### 示例

```bash
# 跳转到 "chapter2" 场景的 #z5 标签
siglus-ssu -e /path/to/SiglusEngine.exe chapter2 5

# .ss 扩展名会自动去除
siglus-ssu -e /path/to/SiglusEngine.exe chapter2.ss z5

# 显式使用 #z 前缀
siglus-ssu -e /path/to/SiglusEngine.exe chapter2 "#z5"
```

---

### `-m` / `--textmap` — 翻译用文本映射

从 `.ss` 源文件或已编译的 `.dat` 文件导出字符串 token 到 CSV "文本映射"，并将已翻译的文本从 CSV 应用回源文件。这提供了一种无需直接编辑 `.ss` 文件的替代翻译工作流。

#### 语法

```
# 从 .ss 源文件导出文本映射
siglus-ssu -m <path_to_ss | path_to_dir>

# 将已翻译的文本映射应用回 .ss 源文件
siglus-ssu -m --apply <path_to_ss | path_to_dir>

# 从已编译的 .dat 文件导出字符串列表
siglus-ssu -m --disam <path_to_dat | path_to_dir>

# 将已翻译的字符串列表应用回已编译的 .dat 文件
siglus-ssu -m --disam-apply <path_to_dat | path_to_dir>
```

#### 参数

| 参数 | 说明 |
|---|---|
| `<path_to_ss \| path_to_dir>` | 单个 `.ss` 文件或包含 `.ss` 文件的目录。**只接受 1 个路径参数**。 |
| `<path_to_dat \| path_to_dir>` | 单个 `.dat` 文件或目录。**只接受 1 个路径参数**。 |
| `--apply`, `-a` | 将 `.ss.csv` 文本映射就地应用回对应的 `.ss` 文件。`.ss.csv` 必须已与 `.ss` 文件并排存在。 |
| `--disam` | 将已编译的 `.dat` 的字符串列表导出到紧邻 `.dat` 的 `.dat.csv` 文件。支持加密、LZSS 压缩或原始 `.dat`。扫描目录时会递归处理 `.dat`，并自动跳过 `Gameexe.dat` 和 `暗号.dat`。 |
| `--disam-apply` | 将 `.dat.csv` 转换后的字符串列表就地应用回已编译的 `.dat`。`--apply`、`--disam`、`--disam-apply` 互斥。 |

#### `.ss` 文件工作流程

1. **导出文本映射：**

   ```bash
   siglus-ssu -m /path/to/scripts/chapter1.ss
   # → 生成 /path/to/scripts/chapter1.ss.csv

   # 整个目录
   siglus-ssu -m /path/to/scripts/
   ```

2. **编辑 `chapter1.ss.csv`：** 在 `replacement` 列填入翻译文本。

   导出的 `.ss.csv` 还会包含一个 `kind` 列：
   `1 = 台词`、`2 = 说话人名`、`3 = 其他文本`。

3. **应用翻译：**

   ```bash
   siglus-ssu -m --apply /path/to/scripts/chapter1.ss
   # 或使用别名
   siglus-ssu -m -a /path/to/scripts/chapter1.ss
   ```

   应用后，工具会自动对修改后的文件执行**括号内容修复**：删除出现在 `【】` 名前括号内的多余双引号和前导空格（这是粘贴翻译文本时的常见问题）。逐文件修复明细会输出到 stderr，最终摘要会输出到 stdout。

#### `.dat` 文件工作流程

1. **导出字符串列表：**

   ```bash
   siglus-ssu -m --disam /path/to/chapter1.dat
   # → 生成 /path/to/chapter1.dat.csv
   ```

2. **编辑 `chapter1.dat.csv`：** 在 `replacement` 列填入翻译文本。

3. **应用翻译：**

   ```bash
   siglus-ssu -m --disam-apply /path/to/chapter1.dat
   ```

   `.dat` 文件被就地重写，保留原始的加密和 LZSS 状态。

#### `.ss.csv` 格式

| 列名 | 说明 |
|---|---|
| `index` | 唯一的顺序 token 索引（从 1 开始）。 |
| `line` | 在源 `.ss` 文件中的行号。 |
| `order` | 该 token 在当前行的出现顺序（从 1 开始）。 |
| `start` | token 内容的绝对字符偏移。 |
| `span_start` | 完整 token 范围（含引号）的绝对起始偏移。 |
| `span_end` | 完整 token 范围的绝对结束偏移。 |
| `quoted` | `1` 表示源码中用 `"..."` 引用，`0` 表示未引用。 |
| `kind` | token 分类：`1 = 台词`、`2 = 说话人名`、`3 = 其他文本`。 |
| `original` | 原始字符串值（转义编码）。 |
| `replacement` | 翻译内容。初始与 `original` 相同，请在此填写翻译。 |

在 `original` 和 `replacement` 中，特殊字符使用转义形式编码：

| 转义 | 含义 |
|---|---|
| `\\` | 字面反斜杠 |
| `\n` | 换行 |
| `\r` | 回车 |
| `\t` | 制表符 |

#### `.dat.csv` 格式

| 列名 | 说明 |
|---|---|
| `index` | 编译后字符串表中的字符串索引（`str_id`）。 |
| `kind` | 字符串分类：`1 = 台词`、`2 = 说话人名`、`3 = 其他文本`。 |
| `original` | 原始字符串值（转义编码）。 |
| `replacement` | 替换后的字符串值。初始与 `original` 相同。 |

---

### `-g` / `--g00` — 处理 `.g00` 图片文件

提供分析、提取、合并、创建和更新 SiglusEngine `.g00` 图片文件的工具，用于背景、立绘等视觉资源。

#### `.g00` 文件类型

| 类型 | 说明 |
|---|---|
| type0 | LZSS32 压缩的 BGRA（32 位）图片。 |
| type1 | LZSS 压缩的调色板图片（最多 256 色）。 |
| type2 | 多 cut 拼合图像（sprite sheet），包含多个按编号索引的 cut。 |
| type3 | XOR 混淆的 JPEG 图片。 |

> **注意：** 除 `--a` 纯分析模式外，当前 `.g00` 的提取、合并、创建和更新都需要 [Pillow](https://pillow.readthedocs.io/)（`pip install pillow`）。

#### 语法

```
# 分析 .g00 文件（无需 Pillow）
siglus-ssu -g --a <input_g00>

# 将 .g00 提取为 PNG/JPEG
siglus-ssu -g --x <input_g00 | input_dir> <output_dir>

# 将多个 .g00 文件（或 cut）合并为单张 PNG
siglus-ssu -g --m <input_g00[:cutNNN]> <input_g00[:cutNNN]> [...] [--o <output_dir>]

# 从图片创建新的 .g00，或基于显式参考 .g00 执行更新
siglus-ssu -g --c [--type N] [--refer <ref_g00 | ref_dir>] <input_png | input_jpeg | input_json | input_dir> [output_g00 | output_dir]
```

#### 参数

| 参数 | 说明 |
|---|---|
| `--a` | **分析**模式。打印类型、画布尺寸、LZSS 统计；对于 type2，还会输出最多前 50 个 cut 的详细信息。 |
| `--x` | **提取**模式。解码每个 `.g00` 并写入 PNG 或 JPEG 文件；对于 type2，还会额外导出一份可回灌的 `.type2.json` sidecar。 |
| `--m` | **合并**模式。将多个 `.g00` 图片或 cut 合成为一张 PNG。 |
| `--c` | **创建/更新**模式。不带 `--refer` 时创建新的 `.g00`；带 `--refer` 时，以参考 `.g00` 为 base 更新图片数据。 |
| `--o <output_dir>`, `-o`, `--output`, `--output-dir` | （仅合并模式）合并后 PNG 的输出目录。可省略；省略时输出到当前工作目录。 |
| `--type N`, `--t N` | （仅 `--c` 模式）在创建模式下强制输出 `.g00` 类型；在更新模式下覆盖参考 `.g00` 的预期类型用于验证。 |
| `--refer <ref_g00 \| ref_dir>` | （仅 `--c` 模式）显式指定更新所用的参考 `.g00`。单文件输入时可传 `.g00` 文件或目录；目录输入时必须传参考目录。若更新模式省略输出路径，单文件输入默认直接写回参考 `.g00`，目录输入默认写回参考目录。 |
| `<g00spec>[:cutNNN]` | 合并模式中，可在路径后附加 `:cutNNN`（如 `bg_day.g00:cut002`）以选择 type2 `.g00` 中的特定 cut。 |

#### 示例

```bash
# 分析 type2 拼合图像
siglus-ssu -g --a /path/to/sprite.g00

# 将目录中所有 .g00 提取为 PNG/JPEG
siglus-ssu -g --x /path/to/g00_dir/ /path/to/png_out/

# 提取单个 .g00
siglus-ssu -g --x /path/to/bg_clear.g00 /path/to/png_out/

# 将两个图像图层合并为一张合成 PNG
siglus-ssu -g --m /path/to/char_base.g00 /path/to/char_eye.g00 --o /path/to/merged_out/

# 合并 type2 .g00 中的特定 cut
siglus-ssu -g --m /path/to/sprite.g00:cut005 /path/to/overlay.g00 --o /path/to/out/

# 从 PNG 创建新的 type0 .g00（输出可省略）
siglus-ssu -g --c /path/to/new_bg.png /path/to/game_bg.g00

# 省略输出路径：在输入图片旁创建 <input_basename>.g00
siglus-ssu -g --c /path/to/new_bg.png

# 从 JPEG 创建新的 type3 .g00
siglus-ssu -g --c /path/to/op.jpeg /path/to/op.g00

# 直接使用 .type2.json 创建或重建 type2 .g00
siglus-ssu -g --c --type 2 /path/to/char_face.type2.json /path/to/char_face.g00

# 从包含多份 .type2.json 的目录批量创建 type2 .g00
siglus-ssu -g --c --type 2 /path/to/layout_dir/ /path/to/out_g00/

# 基于显式参考更新现有 .g00
siglus-ssu -g --c /path/to/new_bg.png /path/to/game_bg.g00 --refer /path/to/original_bg.g00

# 使用参考目录进行批量更新
siglus-ssu -g --c /path/to/updated_pngs/ /path/to/out_g00/ --refer /path/to/original_g00/
```

目录输入的 `-g --x` 会**递归**扫描 `.g00`，但当前实现会把所有输出直接写到同一个 `output_dir`，不保留原始子目录；若不同子目录中存在同名资源，后续同名输出会因为目标已存在而被跳过。

#### 创建模式说明

- 省略 `--refer` 时进入创建模式。
- 当前已实现 **type0**、**type2** 与 **type3** 的创建。
- 默认推断规则：`png` -> type0，`jpg/jpeg` -> type3。创建 type2 时请显式指定 `--type 2` 并直接输入 `.type2.json`。
- 对于 `-g --x` 提取出的多 cut type2，回灌时的创建输入就是自动导出的 `.type2.json`，而不是单张 `*_cutNNN.png`。
- `--c` 的目录输入当前只扫描**当前层**文件，不递归。
- `.type2.json` 只能用于创建/重建 type2；它不能和 `--refer` 一起用于更新模式。
- 更新模式若省略输出路径：单文件时默认直接写回参考 `.g00`，目录模式默认写回参考目录。对原始资产操作前请先备份。
- `type1` 的创建仍未实现。

#### type2 JSON 布局

`type2` 创建由 JSON 布局驱动，不依赖 CutText 或 PSD 元数据。推荐采用下面这份严格 schema：

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

说明：
- 严格 schema 使用的根字段只有：`type`、`canvas`、可选 `default_center`、`cuts`。
- `canvas` 是输出 type2 的画布尺寸。
- `cuts[]` 按 index 排序；可插入 `null` 留空。
- 每个非空 cut 建议显式提供 `source` 与 `canvas_rect`。
- `source` 相对于 JSON 文件路径解析。
- `canvas_rect` 会写入外层 type2 cut 表。
- `source_rect` 为可选；省略时使用整张源图。若同时给出 `source_rect` 与 `canvas_rect`，两者宽高必须一致。
- `center` 为可选，默认继承 `default_center` 或 `(0,0)`。
- 若追求稳定可复现的回灌，建议保留提取时生成的 JSON，只改动明确需要修改的 PNG 像素或矩形/中心点字段。

#### type2 提取与回灌资产

使用 `-g --x` 提取 type2 `.g00` 时，会固定同时导出 JSON sidecar：
- `单 cut`：`<basename>.png` + `<basename>.type2.json`
- `多 cut`：`<basename>_cut000.png`、`<basename>_cut001.png` ... + `<basename>.type2.json`

说明：
- 提取出的 type2 PNG 会**保留 alpha=0 像素下方的 hidden RGB**。
- 自动生成的 `<basename>.type2.json` 是这组提取资产的标准重建布局。
- 重新创建时，程序会**严格尊重输入 PNG 本身**；不会对 hidden RGB 进行恢复、推断或合成。

直接从提取结果回灌：

```bash
# 第一步：提取一个多 cut 的 type2 .g00
siglus-ssu -g --x /path/to/char_face.g00 /path/to/work/

# 会生成：
#   /path/to/work/char_face.type2.json
#   /path/to/work/char_face_cut000.png
#   /path/to/work/char_face_cut001.png
#   ...

# 第二步：直接修改提取出来的 PNG

# 第三步：把 .type2.json 直接作为 -g --c 的输入
siglus-ssu -g --c --type 2 /path/to/work/char_face.type2.json /path/to/rebuilt/char_face.g00
```

对于多 cut type2，真正的创建输入是 `.type2.json`；其中引用的 PNG 会相对于 JSON 文件路径解析。

使用 `--c --refer ...` 更新特定 cut 时，在输入目录中放置名为 `<basename>_cut###.png` 的图片。

---

### `-s` / `--sound` — 处理音频文件

提供解码、提取、分析和重新编码 SiglusEngine 所用音频文件的工具。

#### 支持的格式

| 扩展名 | 说明 |
|---|---|
| `.nwa` | NWA 自适应差分 PCM 压缩音频。解码为 `.wav`。 |
| `.owp` | XOR 混淆的 Ogg Vorbis 音频。解码为 `.ogg`。 |
| `.ovk` | 包含多个编号语音条目的 Ogg Vorbis 文件。提取为单独的 `.ogg` 文件。 |

#### 语法

```
# 提取/解码音频文件
siglus-ssu -s --x <input_dir | input_file> <output_dir> [--trim <Gameexe.dat路径>]

# 分析音频文件（结构信息）
siglus-ssu -s --a <input_file.(nwa | ovk | owp)>

# 创建/重新编码音频文件
siglus-ssu -s --c <input_ogg | input_dir> <output_dir>
```

#### 参数

| 参数 | 说明 |
|---|---|
| `--x` | **提取**模式。解码 `.owp` → `.ogg`，`.nwa` → `.wav`，`.ovk` → 单独的 `.ogg` 文件。 |
| `--a` | **分析**模式。打印单个音频文件的详细结构头部信息。 |
| `--c` | **创建**模式。将 `.ogg` 文件编码为 `.owp`，或将编号的 `.ogg` 文件组合编码为 `.ovk` 文件。目录输入时会递归扫描 `.ogg`，并在输出端保留相对目录结构。 |
| `--trim <Gameexe.dat>` | （仅提取模式）从 `Gameexe.dat` 读取 `#BGM.*` 循环点表，并用 **ffmpeg** 将每个 `.owp` 裁剪到其循环区域。需要 `ffmpeg` 在系统 PATH 中。该选项只影响 `.owp` 提取；`.nwa`/`.ovk` 不参与裁剪。 |

#### 示例

```bash
# 解码目录中的所有音频
siglus-ssu -s --x /path/to/bgm/ /path/to/ogg_out/

# 解码单个 .ovk 语音文件
siglus-ssu -s --x /path/to/z0001.ovk /path/to/ogg_out/

# 解码 .owp BGM 并按 Gameexe.dat 循环点裁剪
siglus-ssu -s --x /path/to/bgm/ /path/to/ogg_out/ --trim /path/to/Gameexe.dat

# 分析 .nwa 文件头
siglus-ssu -s --a /path/to/bgm01.nwa

# 分析 .ovk 归档表
siglus-ssu -s --a /path/to/z0001.ovk

# 分析 .owp 文件
siglus-ssu -s --a /path/to/bgm01.owp

# 将 .ogg 文件重新编码为 .owp
siglus-ssu -s --c /path/to/translated_ogg/ /path/to/owp_out/
```

#### OVK 提取命名规则

提取包含多个条目的 `.ovk` 时，输出文件命名为：
- `<basename>.ogg` — 若只有一个条目。
- `<basename>_<entry_no>.ogg` — 若有多个条目（例如 `z0001_0.ogg`、`z0001_1.ogg`）。

#### OVK 创建命名规则

从目录创建 `.ovk` 时，命名为 `<basename>_<N>.ogg`（N 为整数）的文件只有在同组至少存在两份时，才会被分组打包为单个 `<basename>.ovk`。若某组只有一份带数字后缀的文件，当前实现会把它按普通单文件输入处理并输出 `.owp`。不带数字后缀的文件也会单独编码为 `.owp`。

#### `.owp` 裁剪细节

`--trim` 会读取 Gameexe.dat 中的 BGM 表（条目格式为 `#BGM.N = "...", "filename", start, end, repeat`），并调用 **ffmpeg** 将每个解码得到的 `.ogg` 裁剪到 `repeat` 与 `end` 之间的采样区间。这对提取可无缝循环的背景音乐很有帮助。

目录输入的 `-s --x` 也会递归扫描子目录，并在输出端保留相对目录结构。

---

### `-v` / `--video` — 处理 `.omv` 视频文件

提供分析、提取和重新编译 `.omv` 视频文件的工具。`.omv` 格式是带有专有 SiglusEngine 包装头的 Ogg 容器（`.ogv`）。

#### 语法

```
# 将 .omv 提取为 .ogv（原始 Ogg 视频）
siglus-ssu -v --x <input_dir | input_file.omv> <output_dir>

# 分析 .omv 文件（结构信息）
siglus-ssu -v --a <input_file.omv>

# 将 .ogv 包装为 .omv
siglus-ssu -v --c <input_ogv> <output_omv | output_dir> [--refer ref.omv] [--mode N] [--flags 0x...]
```

#### 参数

| 参数 | 说明 |
|---|---|
| `--x` | **提取**模式。去除 SiglusEngine 包装层并写入纯 `.ogv` 文件。 |
| `--a` | **分析**模式。打印详细头部信息，包括外层头字段、TableA 和 TableB 帧元数据；若可解析，还会输出 Theora 流信息，如 FPS、keyframe granule shift、pixel format 和画面尺寸。 |
| `--c` | **创建**模式。用 SiglusEngine `.omv` 头包装纯 `.ogv`。 |
| `--refer <ref.omv>` | 从现有的 `.omv` 参考文件复制头部 `mode` 和 TableB `flags_hi24`。若同时指定了 `--mode`/`--flags` 则会被覆盖。 |
| `--mode N` | 覆盖 `mode` 字段（头部偏移 `0x28`）。接受十进制或 `0x...` 十六进制。 |
| `--flags 0xXXXXXX` | 覆盖 TableB `flags` 的高 24 位。接受单个值或逗号分隔的范围规格，如 `0-9:0x1A2B3C00,10-:0x00000000`。 |

目录输入的 `-v --x` 会递归扫描 `.omv`，并在输出端保留相对目录结构。`-v --c` 在判断第二个参数时遵循这样的规则：若参数是已存在目录、以路径分隔符结尾，或没有扩展名，则按“输出目录”处理；若想明确写到单个文件，请给出带 `.omv` 扩展名的文件路径。

#### 示例

```bash
# 将目录中所有 .omv 提取为 .ogv
siglus-ssu -v --x /path/to/movie/ /path/to/ogv_out/

# 分析单个 .omv
siglus-ssu -v --a /path/to/op.omv

# 使用原始头部元数据将 .ogv 重新打包为 .omv
siglus-ssu -v --c /path/to/op_translated.ogv /path/to/op_translated.omv --refer /path/to/op_original.omv

# 手动指定 mode 和 flags
siglus-ssu -v --c /path/to/op.ogv /path/to/op.omv --mode 10 --flags 0x19DC00
```

---

### `-p` / `--patch` — 修改 `SiglusEngine.exe`

对 `SiglusEngine.exe` 进行二进制补丁。支持两种操作：

- **`--altkey`**：用另一个密钥替换内嵌的 `exe_el` 解密密钥。
- **`--lang`**：应用语言预设（`chs` 或 `eng`）或自定义 JSON 映射，使引擎加载不同的 `.pck` 文件、存档目录和字符编码。

#### 语法

```
# 修改内嵌的 exe_el 密钥
siglus-ssu -p --altkey <input_exe> <input_key> [-o output_exe] [--inplace]

# 应用语言补丁
siglus-ssu -p --lang (chs | eng | <json>) <input_exe> [-o output_exe] [--inplace]
```

#### 参数

| 参数 | 说明 |
|---|---|
| `<input_exe>` | 要修改的 `SiglusEngine.exe` 路径。 |
| `<input_key>` | **（仅 --altkey）** 新的 16 字节密钥。接受：字面格式如 `0xA9, 0x86, ...`；`key.txt`；`暗号.dat`；`SiglusEngine*.exe`；或目录（自动推导）。 |
| `-o`, `--output` | 输出的修改后可执行文件路径。默认为 `<stem>_alt.exe`（altkey）或 `<stem>_CHS.exe`/`<stem>_ENG.exe`（lang）。 |
| `--inplace` | 直接覆盖输入文件，而非写入新路径。若同时给出 `-o/--output`，则以 `--inplace` 为准。 |
| `--lang chs` | 应用内置简体中文预设。 |
| `--lang eng` | 应用内置英文预设。 |
| `--lang <json>` | 应用自定义 JSON 规格的补丁（见下文）。这里的 `<json>` 是**内联 JSON 字符串**，不是 JSON 文件路径。 |

#### 语言补丁预设

**`--lang chs`** 执行以下修改：
- 将 `lfCharSet` 设为 `0x86`（GBK/GB2312 中文）。
- 替换：`Scene.pck` → `Scene.chs`，`savedata` → `savechs`，`japanese` → `chinese`，`Gameexe.dat` → `Gameexe.chs`。

**`--lang eng`** 执行以下修改：
- 将 `lfCharSet` 设为 `0x00`（ANSI/Latin）。
- 替换：`Scene.pck` → `Scene.eng`，`savedata` → `saveeng`，`japanese` → `english`，`Gameexe.dat` → `Gameexe.eng`。

#### 自定义 JSON `--lang` 配置

```json
{
  "charset": 0,
  "suffix": "ENG",
  "replace": {
    "Scene.pck": "Scene.eng",
    "savedata": "saveeng"
  },
  "skip_standalone": ["savedata"]
}
```

| JSON 字段 | 说明 |
|---|---|
| `charset` | 目标 `lfCharSet` 值。接受 `0`/`"eng"`（ANSI）、`128`/`"jp"`（Shift-JIS）、`134`/`"chs"`（GBK），或任意整数。 |
| `suffix` | 默认输出文件名的后缀（如 `"ENG"` → `SiglusEngine_ENG.exe`）。 |
| `replace` | 旧字符串 → 新字符串的映射对象（UTF-16LE 原地替换）。新字符串不得比旧字符串长。 |
| `skip_standalone` | 当旧字符串以 NUL 字节为邻（即在内存中孤立出现而非路径的一部分）时跳过替换的字符串列表。 |

#### 示例

```bash
# 使用 key.txt 修改 exe_el 密钥
siglus-ssu -p --altkey /path/to/SiglusEngine.exe /path/to/key.txt -o /path/to/SiglusEngine_patched.exe

# 使用字面 16 字节密钥修改 exe_el
siglus-ssu -p --altkey /path/to/SiglusEngine.exe "0xA9, 0x86, 0x3F, 0x12, 0x5E, 0xC1, 0x78, 0x04, 0xBB, 0xA1, 0xF2, 0x93, 0xD4, 0x7E, 0x60, 0x55"

# 使用 暗号.dat 推导的密钥原地修改
siglus-ssu -p --altkey /path/to/SiglusEngine.exe /path/to/暗号.dat --inplace

# 应用英文语言补丁
siglus-ssu -p --lang eng /path/to/SiglusEngine.exe

# 原地应用中文语言补丁
siglus-ssu -p --lang chs /path/to/SiglusEngine.exe --inplace

# 应用自定义 JSON 语言补丁
siglus-ssu -p --lang '{"charset":0,"suffix":"ENG","replace":{"Scene.pck":"Scene.eng"}}' /path/to/SiglusEngine.exe
```

#### 输出

patch 命令会在写入输出文件前，将变更摘要打印到 stdout：

```
Input : /path/to/SiglusEngine.exe
Mode  : lang:eng
SHA256(before): abc123...
SHA256(after) : def456...
Applied changes: N bytes
 - lfCharSet: -> 0x00 (N bytes)
 - Scene.pck -> Scene.eng (N bytes)
 - savedata -> saveeng (N bytes)
 - japanese -> english (N bytes)
 - Gameexe.dat -> Gameexe.eng (N bytes)
Written: /path/to/SiglusEngine_ENG.exe
```


<a id="siglusss-language-spec"></a>
## SiglusSceneScript语言规范（简称 SiglusSS语言；以 `-c` 编译器为定义）

本节把 `siglus-ssu -c` 当前编译器对 **SiglusSceneScript语言**（简称 **SiglusSS语言**）的接受、拒绝与链接行为，视为该语言的规范定义，而不是“仅供参考的实现说明”。除非另有说明，本节中的“应”“不得”“可以”分别表示强制、禁止、允许。

本规范覆盖的对象，是在给定 `const.py` 与 `--const-profile` 下、面向 `.ss` 源文件与同目录 `.inc` 文件的编译前端与目录级链接约束。`const.py` / `--const-profile` 改变的是：

- 可用 form 名称；
- 内建 property / command 集；
- 某些 profile 相关的额外静态限制。

它们**不**改变本节给出的核心字符预处理、词法、句法骨架和大多数静态规则。

### 一致性原则

一个实现若要与当前编译器一致，则在同一 `const-profile`、同一 `.inc` 集合、同一输入目录与同一条件下，应当满足：

1. 对每个翻译单元做出与当前编译器相同的接受/拒绝决定；
2. 对每个名字、label、z-label、property、command 与表达式 form 做出与当前编译器相同的解析结果；
3. 对目录级全局 `#command` 的实现唯一性与缺失实现，做出与当前 linker 相同的判定；
4. 对本节明确记载的实现怪癖，也应当保持一致，因为它们已经构成现行语言定义的一部分。

### 术语与翻译环境

#### 源文件集合

对单个 `.ss` 文件而言，其编译环境不是该文件自身，而是：

- 当前 `.ss` 文件；
- 与其位于同一目录的全部 `.inc` 文件；
- 由活动 `const.py` / `--const-profile` 提供的 form 与内建元素表。

同目录 `.inc` 文件按**文件名的小写排序**处理。

#### 解码与行结束符

`-c` 模式先把源文件按输入编码解码为文本；该编码可以由 `--charset` 指定，也可以由编译器自动探测。字符解码之后，所有 `\r` 都会先被删除。因此，SiglusSS语言的后续规则是以“去掉 `\r` 的文本流”为对象定义的。

#### 规范术语

- **scene 文本**：`.ss` 文件中除 `#inc_start ... #inc_end` 区段以外、进入普通 scene 语法分析的部分；
- **scene 内嵌 inc 区段**：`.ss` 文件中由 `#inc_start` 与 `#inc_end` 包围、按 `.inc` 声明语法解释的部分；
- **全局 `.inc` 环境**：同目录全部 `.inc` 文件处理后得到的声明、替换和名字集；
- **良构程序**：在本规范全部前端与链接约束下被接受的源程序。

### 翻译阶段

对于一个 `.ss` 翻译单元，当前编译器的处理顺序可规范化为：

1. 读取并解码源文本；
2. 删除 `\r`；
3. 对 scene 源文本做字符级处理：删除注释、在字符串与注释外折叠 ASCII 大写字母、处理 `#ifdef` / `#elseifdef` / `#else` / `#endif`，并抽取 `#inc_start ... #inc_end` 区段；
4. 先将抽取出的 scene 内嵌 inc 区段作为 `.inc` 文本，用 parent form = `scene` 的 `IncAnalyzer` 处理；
5. 把上一步产生的声明和替换环境并入当前文件环境；
6. 对 scene 文本执行替换展开；
7. 对替换后的 scene 文本执行词法分析（LA）、语法分析（SA）、语义分析（MA）与字节码生成（BS）；
8. 当 `-c` 面向目录整体编译时，在所有 scene 前端阶段结束后，再执行目录级 linker 检查。

由此可知，下列事实都是规范性的：

- scene 级 `#ifdef` / `#elseifdef` / `#else` / `#endif` 发生在 scene 内嵌 inc 被分析**之前**；因此，scene 级条件编译看不到同一 `.ss` 文件稍后由 `#inc_start ... #inc_end` 声明出来的新名字；
- 目录级 compile 的语言定义，严格大于“单个 `.ss` 文件局部通过前端检查”。

### 字符级处理

#### 大小写折叠

在字符串字面量、字符字面量与注释之外，ASCII `A` 至 `Z` 应先折叠为对应的小写字母。因此：

- ASCII 关键字大小写不敏感；
- ASCII 标识符、label、directive 名大小写不敏感；
- 非 ASCII 字符不参与该折叠。

#### 注释

SiglusSS语言与 `.inc` 声明文本都接受以下三种注释：

- `;` 到行末；
- `//` 到行末；
- `/* ... */` 块注释。

`/* ... */` 不嵌套。未闭合块注释是错误。注释起始记号在单引号与双引号内部不生效。

#### 条件编译

scene 文本与 `.inc` 文本都支持：

```text
#ifdef <word>
#elseifdef <word>
#else
#endif
```

其规则如下：

1. `#ifdef` 与 `#elseifdef` 测试的是“名字是否属于当前 `name_set`”，而不是某个数值真假；
2. 条件嵌套最大深度为 15 层；当进入第 16 层时应报错；
3. 缺失配对的 `#else`、`#elseifdef`、`#endif`，以及未闭合的 `#ifdef`，均是不良构；
4. `<word>` 的提取方式不是普通 scene 标识符规则，而是一个更宽松的 `word-ex` 规则：首字符可为 ASCII 字母、全角/双字节字符、`_`、`@`；后续字符还可再包含数字。

#### `#inc_start` / `#inc_end`

这对指令只在 scene 文件字符级处理阶段使用。其规则如下：

1. `#inc_start` 开始收集 scene 内嵌 inc 区段；
2. `#inc_end` 结束该区段；
3. 当前实现把它当作布尔状态而不是嵌套计数器处理，因此它**不支持嵌套**；
4. 缺失配对的 `#inc_end` 或未闭合的 `#inc_start` 都是不良构。

#### 源元数据注释

若源文件第一行形如：

```text
// #SCENE_SCRIPT_ID = dddd
```

其中 `dddd` 为四位十进制数字，则编译器会把它识别为场景元数据。该注释不改变核心语法与静态语义，但属于当前实现接受的源格式组成部分。

### 词法结构

#### 空白与换行

空白字符为：

- 空格；
- TAB；
- 换行。

换行不是语句终止符。SiglusSS语言没有分号语句结束符。

#### 标识符

scene 文本中的普通标识符遵循：

```text
identifier ::= identifier-start { identifier-continue }
identifier-start ::= "_" | "$" | "@" | ascii-letter
identifier-continue ::= identifier-start | digit
```

其中 `ascii-letter` 在大小写折叠之后等价于 `a ... z`。

保留关键字为：

```text
command  property  goto  gosub  gosubstr  return
if  elseif  else  for  while  continue  break
switch  case  default
```

#### 标签与 z-label

label token 以 `#` 开始：

```text
label-token ::= "#" { "_" | ascii-letter | digit }
z-label-token ::= "#z" digit [digit [digit]]
```

规范含义如下：

1. 普通 label 在词法上**可以为空名**；因此单独的 `#` 也会被词法化为普通 label；
2. 仅当拼写恰为 `#z` 后跟 1 至 3 个十进制数字时，才是 z-label；
3. `#z0`、`#z00`、`#z000` 都属于 z-label；`#z1234` 不是；
4. label 与 z-label 的重定义、未定义引用，以及 `#z0` 缺失，都由后续阶段判错。

#### 整数字面量

支持三类整数字面量：

```text
decimal ::= digit { digit }
binary  ::= "0b" { "0" | "1" }
hex     ::= "0x" { hex-digit }
```

其语义规则如下：

1. 词法阶段即按**有符号 32 位整数**累积；
2. 溢出按 `i32` 回绕；
3. 负号不是字面量的一部分，而是一元运算符。
4. 裸写的 `0b` 或 `0x` 也会被接受，并被当作数值 `0`。

#### 字符与字符串字面量

单引号字面量与双引号字面量都不得跨物理行。允许的转义序列只有：

- `\\`
- `\n`
- 与当前引号种类对应的 `\'` 或 `\"`

单引号字面量在转义解释后必须产生且只产生**一个字符**；否则是不良构。其词法结果为 `VAL_INT`。双引号字面量的词法结果为 `VAL_STR`。

#### 全角/双字节裸字符串

凡被 `_iszen()` 判定为双字节或全角的连续字符序列（不含 `【` 与 `】`），都会直接词法化为 `VAL_STR`。因此，以下两种写法在词法上都能形成字符串 token：

```text
"你好"
你好
```

这也是 `【角色名】` 与裸台词行能够成立的基础。

#### 界符与运算符

界符为：

```text
.  ,  :  (  )  [  ]  {  }  【  】
```

赋值运算符只用于语句，不形成表达式：

```text
=  +=  -=  *=  /=  %=  &=  |=  ^=  <<=  >>=  >>>=
```

表达式运算符优先级，自低到高如下：

| 级别 | 运算符 | 结合性 |
|---|---|---|
| 1 | `||` | 左结合 |
| 2 | `&&` | 左结合 |
| 3 | `\|` | 左结合 |
| 4 | `^` | 左结合 |
| 5 | `&` | 左结合 |
| 6 | `==`, `!=` | 左结合 |
| 7 | `>`, `>=`, `<`, `<=` | 左结合 |
| 8 | `<<`, `>>`, `>>>` | 左结合 |
| 9 | `+`, `-` | 左结合 |
| 10 | `*`, `/`, `%` | 左结合 |
| 一元 | `+`, `-`, `~` | 前缀 |

### `.inc` 声明语言

全局 `.inc` 文件与 scene 内嵌 inc 区段，共享同一套声明语法。在注释剔除与大小写折叠后，它们应仅由空白和以下声明构成：

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

#### 名字提取规则

`.inc` 中各类名字不是统一用 scene 标识符规则提取，而是由声明种类分别决定：

- `#replace` / `#define` 名字遇到空格、TAB 或换行结束；
- `#define_s` 名字遇到 TAB 或换行结束，因此**可以包含空格**；
- `#property` 名字遇到空格、冒号、TAB 或换行结束；
- `#command` 名字遇到空格、`(`、冒号、TAB 或换行结束；
- `#command` 与 `#property` 名字因此可以超出 scene 普通标识符字符集；
- 宏名必须以 `@` 开头；
- 上述各类声明共享同一个 `name_set`：若某名字已经存在，则重复声明是不良构；成功声明后，该名字会立即加入 `name_set`，从而影响后续 `#ifdef` / `#elseifdef` 的判定。

#### `#replace`、`#define`、`#define_s`

```text
replace-decl   ::= "#replace"  name replacement-text
define-decl    ::= "#define"   name replacement-text
define-s-decl  ::= "#define_s" name-s replacement-text
```

`replacement-text` 的抽取规则如下：

1. 名字之后先跳过前导空白；
2. 读到下一个未转义的 `#` 或文件结束为止；
3. 期间换行折叠为空格；
4. 末尾空格与 TAB 被裁剪；
5. `##` 代表字面 `#`；
6. 其中允许再出现 `#ifdef` / `#elseifdef` / `#else` / `#endif`。

展开语义如下：

- `#replace`：替换完成后，扫描位置推进到替换结果之后；因此该次替换插入的文本不会在同一位置立即再次重扫；
- `#define` 与 `#define_s`：替换完成后，扫描位置保持在原处；因此插入文本会立即再次参与展开。

替换系统还有两个规范性细节：

1. 在单个替换树内部，匹配选择采用**最长前缀命中**；
2. 当默认替换树与临时附加替换树在同一位置都命中时，当前实现用候选项 `name` 字段的**词典序较大者**作为胜者，而不是按声明先后或“跨树全局最长匹配”择优；一致实现应复现这一规则。

为防止无限展开，当前实现设置了“超过阈值仍无前进”的保护。达到该保护条件时，程序是不良构的。

#### `#macro`

```text
macro-decl ::= "#macro" macro-name ["(" macro-param {"," macro-param} ")"] replacement-text
macro-name ::= "@" <non-space-sequence>
macro-param ::= param-name ["(" default-text ")"]
```

其规则如下：

1. 宏属于文本替换，不是语义级调用；
2. 实参与默认文本都按原始文本处理；
3. 如果写了括号，参数列表就必须至少有一个参数；空的 `()` 不被接受。
4. 宏实参的分割遵循括号层级；字符串和字符字面量内部的逗号、括号不参与外层分割；
5. 宏展开结果会再次参与当前替换流程。

#### `#property`

```text
property-decl ::= "#property" name [":" form-name ["[" integer-literal "]"]]
```

其规则如下：

1. 缺省 form 为 `int`；
2. `void` 不得作为 property form；
3. 数组后缀只允许用于 `intlist` 与 `strlist`；
4. 数组大小必须是十进制整数常量，而不是一般表达式。

#### `#command`

```text
command-decl ::= "#command" name ["(" inc-arg {"," inc-arg} ")"] [":" form-name]
inc-arg ::= form-name ["(" default-literal ")"]
default-literal ::= signed-int-literal | double-quoted-string
```

其规则如下：

1. 缺省返回 form 为 `int`；
2. `.inc #command` 形参只写 form 与默认值，不写参数名；
3. 如果写了括号，参数列表就必须至少有一个参数；空的 `()` 不被接受。
4. 一旦某个形参声明了默认值，则其后的全部形参也都应声明默认值；
5. 语法允许 `int` 与 `str` 默认值；
6. 但是当前 BS 阶段自动补齐缺省实参时，只真正支持“剩余 `int` 默认值”；省略剩余字符串默认参数会在 BS 阶段报错。因此，这一限制同样属于现行语言定义的一部分。

#### `#expand`

```text
expand-decl ::= "#expand" replacement-text
```

`#expand` 会立即按当前替换环境展开其文本，并把展开结果回插到当前 `.inc` 源中，随后从插入点继续进行 `.inc` 声明分析。

### scene 句法

除去 scene 内嵌 inc 区段之后，普通 scene 文本按以下骨架分析：

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

#### 基本语句

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

应特别注意：

1. `switch` / `case` / `default` **不带冒号**；`case(exp)` 之后直接接语句序列；
2. `for` 三段子句由逗号分隔，不使用分号；
3. `for` 的初始化段与循环段不是表达式，而是“零个或多个 sentence 的序列”；
4. `name-stmt` 只能包含单个字符串 token；
5. 独立出现的字符串 token 本身就是合法文本语句。

#### form、元素表达式与实参表

```text
form ::= form-name ["[" exp "]"]
arg-list ::= "(" [arg {"," arg}] ")"
arg ::= exp | identifier "=" exp

elm-exp ::= element { "." element | "[" exp "]" }
element ::= identifier [arg-list]
```

补充规则：

1. `form-name` 必须出现在活动 form 表中；
2. 命名实参与位置实参在语法上可以混写；语法分析完成后，命名实参会被重排到实参序列尾部，并保持“位置实参与命名实参各自内部的原相对顺序”；
3. scene `property` 与 `command` 形参中出现的 `form[exp]`，只要求索引表达式 form 为 `int`；当前实现不会像 `.inc #property` 一样把它解释成真正保留大小元数据的数组声明。

#### 表达式

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

其中：

- 列表字面量 `[...]` 至少包含一个元素；空列表 `[]` 不被接受；
- `goto`、`gosub`、`gosubstr` 既能作为语句，也能作为表达式参与更大表达式。

### 名称查找与 form 规则

#### 根名字查找顺序

根名字按以下顺序解析：

```text
call  ->  scene  ->  global
```

其中：

- `call` 为当前 command 调用帧；
- `scene` 为当前场景空间；
- `global` 包含 `.inc` 全局声明与 profile 提供的内建元素。

元素链 `a.b[c].d(...)` 的后续解析，由前一段元素的 form 决定。可访问的成员集由当前 form table 决定，因此它本身是 profile 参数化的。

#### property 的引用 form

当元素链最终解析到 property 时，其表达式 form 会提升为引用 form：

- `int` -> `intref`
- `str` -> `strref`
- `intlist` -> `intlistref`
- `strlist` -> `strlistref`

因此，赋值左侧应当是能解析为引用 form 的元素表达式。

#### 特殊的“未解析单段名字退化为字符串”规则

若某个简单表达式同时满足：

1. 它是仅含**单段**元素的 `elm-exp`；
2. 该段没有实参表；
3. 名称查找失败；
4. 该名字既不含 `@`，也不含 `$`；

则它不会报“未知元素”，而是被改写为同名字符串字面量。这一规则是语言定义本身的一部分，而不是错误恢复行为。

### 类型与静态约束

#### 一元与二元运算

当前实现接受的主要 form 规则如下：

1. 一元 `+`、`-`、`~`：操作数应为 `int` 或 `intref`，结果为 `int`；
2. 当左右两侧均为 `int` / `intref` 时，`+ - * / % == != > >= < <= && || & | ^ << >> >>>` 都成立，结果为 `int`；
3. 当左右两侧均为 `str` / `strref` 时：
   - `+` 结果为 `str`；
   - `== != > >= < <=` 结果为 `int`；
4. `str` / `strref` 与 `int` / `intref` 的 `*` 结果为 `str`；
5. 反向的 `int * str` 不成立；
6. 赋值运算不是表达式，只能出现在 `call-or-assign-stmt` 中。

#### 赋值

赋值语句应满足：

1. 左值必须是引用 form；
2. `intref` 可接受 `int` 与 `intref`；
3. `strref` 可接受 `str` 与 `strref`；
4. 其他引用 form 需要与右侧严格匹配。

#### 语句级约束

1. `property` 语句只能出现在 `command` 体内部；顶层虽然能被语法识别，但语义上是不良构；
2. `if`、`for`、`while` 的条件应为 `int` 或 `intref`；
3. `switch` 条件应为 `int` / `intref` / `str` / `strref`；每个 `case` 值必须与条件同属整数家族或字符串家族；
4. `goto` 表达式 form 为 `void`；`gosub` 为 `int`；`gosubstr` 为 `str`；
5. `continue` 与 `break` 在循环外使用，将在 BS 阶段报错；
6. 某些 profile 标记为“选择分支相关”的命令，不得出现在条件、普通实参、goto 实参或下标表达式中；这是 profile 相关的额外静态限制；
7. `name-stmt` 产生名字显示事件；`text-stmt` 产生文本显示事件，并消耗一个 read flag 序号。

#### command 定义与声明匹配

scene 中的 `command` 定义有两种来源：

1. 它可能是纯 scene 局部命令；
2. 它可能是在 `.inc` 中预先声明过的全局 `#command` 的实现。

当一个 scene `command` 被用来实现 `.inc #command` 时，当前编译器检查：

- 返回 form 必须一致；
- 位置形参数量必须一致；
- 每个位置形参的 form 必须一致。

但它**不**要求：

- scene 侧参数名与 `.inc` 声明“等价”；
- scene 侧参数默认值与 `.inc` 声明“等价”。

因此，现行语言定义中，`.inc #command` 的“实现匹配”是以返回 form 与位置参数 form 序列为准，而不是以参数名或默认值为准。

#### `return` 的当前约束范围

当前编译器不会再做一条额外的独立检查，来保证 `return(exp)` 的表达式 form 与 command 声明返回 form 一致。调用点的类型推断仍以 command 的声明 form 为准。因此，一致实现也应复现这一现状。

#### 命名实参

命名实参是否被接受，取决于被调用元素的签名表是否提供命名实参映射。对接受命名实参的调用，编译器按名字检查其目标槽位与 form；未知命名实参或 form 不匹配都是错误。

### 全文件与目录级约束

#### label 与 z-label

一个 scene 文件应满足：

1. 普通 label 不得重定义；
2. z-label 不得重定义；
3. 所有被引用的 label 与 z-label 都应存在；
4. `#z0` 必须存在；
5. 所有 scene 局部 `command` 声明都必须在该文件内得到定义。

#### 全局 `.inc #command` 的目录级链接

当 `-c` 对整个目录编译并最终打包时，还应满足：

1. 全局 `.inc` 中声明的 `#command` 会进入目录级命令表；
2. 每个此类全局 `#command` 都应由**恰好一个** scene 提供实现；
3. 若某命令被多个 scene 实现，linker 判为“defined more than once”；
4. 若某命令没有任何 scene 实现，linker 判为“is not defined”。

当前实现还有一个需要视为规范的怪癖：只有当 linker 在整个目录里至少见到过一个 scene `command` 标签之后，才会执行“缺失实现”检查。如果整个目录里完全没有任何 scene `command` 定义，当前 linker 不会报“is not defined”。

因此，一个实现若只复现单文件前端，而不复现该目录级约束，就不能视为与当前 `-c` 语言定义完全一致。


## 提示与故障排除

### `const.py is missing. Run 'siglus-ssu init' first.`

您从 PyPI 安装了软件包但尚未运行初始化步骤：

```bash
siglus-ssu init
```

### 编译时出现 token 错误

若编译时报告意外 token 错误，请检查报告行号附近的 `.ss` 文件。包含逗号、括号或日文引号括号的字符串可能需要用双引号包裹：

```
# 修改前（逗号可能混淆解析器）
mes(【主角】, 等一下，我需要考虑一下。)

# 修改后（始终安全）
mes(【主角】, "等一下，我需要考虑一下。")
```

### 匹配混淆种子

本工具支持用 MSVC 兼容 `rand()` 种子复现 `.dat` 字符串表的位置乱序。翻译工作通常**不需要**复现这一点；只有在追求逐字节一致输出时，才需要关心种子问题。

若需要逐字节相同的输出，先尝试找到种子：

```bash
siglus-ssu -c --test-shuffle /path/to/src/ /path/to/out/ /path/to/original_dats/
```

若成功找到，使用该种子编译：

```bash
siglus-ssu -c --set-shuffle <找到的种子> /path/to/src/ /path/to/out/
```

> **注意：** 在极少数情况下，单个初始种子可能无法完全逐字节复现位置混淆。这可能是因为原开发者在构建时使用了增量编译（我们也通过 `--tmp` 选项支持），这会改变文件的编译顺序，从而改变 `rand()` 调用的顺序。

### 兼容性提示：字符串乘整数的异构乘法

官方编译器在普通二元 `*` 表达式上，会把右侧 form 按左操作数 (`exp_1`) 写入。本项目有意改为语义上更自然的右操作数 form (`exp_2`)。

有问题的语法，具体是指“作为取值使用的普通二元 `*` 表达式，并且其左操作数解引用后是字符串类、右操作数解引用后是整数类”。例如 `set_namae("ABC" * 3)`、`set_namae(s[0] * a[0])`、`s[0] = "ABC" * 3` 都属于这一类。

如果您需要一种在官方 `exp_1` 与本项目 `exp_2` 下都会编译出相同结果的源码写法，经验证可用的兼容写法是：先落到字符串引用上，再使用 `*=`。这个改写可以保持在同一行：

```ss
s[0] = "ABC" s[0] *= 3 set_namae(s[0])
```

不要改写成 `s[0] = s[0] * 3`，因为它仍然属于同一种有问题的普通二元 `*` 表达式。

### 未安装 Pillow（G00 模式）

G00 图片模式中，除 `--a` 纯分析外，当前都需要 [Pillow](https://pillow.readthedocs.io/)：

```bash
pip install pillow
```

### 找不到 ffmpeg（Sound 裁剪模式）

Sound 模式的 `--trim` 功能需要 `ffmpeg` 安装并在系统 PATH 中可用。请从 https://ffmpeg.org/ 或通过系统包管理器安装。

### 使用纯 Python 回退

若遇到 Rust 原生扩展问题，可使用 `--legacy` 标志强制使用纯 Python 实现：

```bash
siglus-ssu --legacy -c /path/to/src/ /path/to/out.pck
```

注意纯 Python 实现在大型项目中速度明显更慢。

### Termux / 无预构建 wheel 的平台

Termux（Android）没有预先构建好的 wheel。您必须手动构建 Rust 扩展，这需要安装 Rust 工具链（`rustup`）和适合您架构的交叉编译工具链，此过程具有一定难度。
