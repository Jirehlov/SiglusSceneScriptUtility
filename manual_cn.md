# SiglusSceneScriptUtility 使用手册

*本文档由 Claude Opus 4.6 Thinking 生成。*

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
   - [获取帮助](#获取帮助)
4. [模式参考](#模式参考)
   - [init — 下载运行时常量](#init--下载运行时常量)
   - [-c / --compile — 编译脚本](#-c----compile--编译脚本)
   - [-x / --extract — 提取文件](#-x----extract--提取文件)
   - [-a / --analyze — 分析和比较文件](#-a----analyze--分析和比较文件)
   - [-d / --db — 导出和编译 `.dbs` 数据库](#-d----db--导出和编译-dbs-数据库)
   - [-k / --koe — 按角色收集语音文件](#-k----koe--按角色收集语音文件)
   - [-e / --exec — 从指定标签启动引擎](#-e----exec--从指定标签启动引擎)
   - [-m / --textmap — 翻译用文本映射](#-m----textmap--翻译用文本映射)
   - [-g / --g00 — 处理 `.g00` 图片文件](#-g----g00--处理-g00-图片文件)
   - [-s / --sound — 处理音频文件](#-s----sound--处理音频文件)
   - [-v / --video — 处理 `.omv` 视频文件](#-v----video--处理-omv-视频文件)
   - [-p / --patch — 修改 `SiglusEngine.exe`](#-p----patch--修改-siglusengineexe)
5. [提示与故障排除](#提示与故障排除)

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

---

## 基本用法

```
siglus-ssu [-h] [-V | --version] [--legacy] <模式> [参数]
```

### 全局选项

| 选项 | 说明 |
|---|---|
| `-h`, `--help` | 显示帮助信息并退出。 |
| `-V`, `--version` | 显示程序版本并退出。 |
| `--legacy` | 禁用 Rust 原生加速，使用纯 Python 回退实现。可用于调试。 |

### 获取帮助

```bash
# 显示全局帮助，列出所有模式
siglus-ssu --help

# 模式特定帮助通常通过省略必需参数来触发
siglus-ssu -c --help
```

---

## 模式参考

### `init` — 下载运行时常量

从项目 GitHub 仓库下载 `const.py` 文件，其中包含引擎特定的常量（操作码表、密钥推导参数等）。

**每次从 PyPI 新鲜安装后必须运行一次。从源码构建时不需要此步骤。**

#### 语法

```
siglus-ssu init [--force | -f] [--ref <git-ref>]
```

#### 参数

| 参数 | 说明 |
|---|---|
| `--force`, `-f` | 即使已存在 `const.py` 也强制覆盖。 |
| `--ref <git-ref>` | 从指定的 Git 分支、标签或提交哈希下载 `const.py`。默认：`main`。 |

#### 示例

```bash
# 基本初始化（从 main 分支下载）
siglus-ssu init

# 覆盖已有的 const.py
siglus-ssu init --force

# 从特定标签下载
siglus-ssu init --ref v0.1.11
```

---

### `-c` / `--compile` — 编译脚本

将一个目录中的 `.ss` SceneScript 源文件编译为 `.pck` 文件（或一个包含编译后 `.dat` 文件的目录）。编译流程精确复现官方 SiglusEngine 构建系统，包括 LZSS 压缩、每脚本字符串表乱序、以及基于 `暗号.dat` 的加密。

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
| `<output_pck \| output_dir>` | 输出路径。若以 `.pck` 结尾，则写入该文件；若为目录路径，则在其中创建 `Scene.pck`。 |
| `--debug` | 编译后保留中间临时文件（`.dat`、`.lzss` 等），并打印各阶段耗时统计。 |
| `--charset ENC` | 强制指定源文件编码。接受值：`jis`、`cp932`、`sjis`、`shift_jis`（均等价于 Shift-JIS）或 `utf8`、`utf-8`。省略时自动检测。 |
| `--no-os` | 跳过 OS（原始源码）打包阶段。编译后的 `.dat` 放入输出目录但不打包为 `.pck`。不影响文件本身的加密或压缩。 |
| `--dat-repack` | 不编译 `.ss` 脚本，而是扫描 `input_dir` 中现有的 `.dat` 文件并将它们直接打包成一个 `.pck` 文件。这对于打包已经编译好的脚本非常有用。兼容且只能与 `--no-os` 结合使用。不能与 `--test-shuffle` 同用。 |
| `--no-angou` | 禁用 LZSS 压缩和 XOR 加密（`header_size=0`）。可用于调试或无加密的引擎。 |
| `--parallel` | 启用多进程并行编译以加速大型项目。 |
| `--max-workers N` | 最大并行工作进程数。默认为 CPU 核心数。 |
| `--lzss-level N` | LZSS 压缩级别，`2`（快，文件大）到 `17`（慢，文件最小）。默认：`17`。 |
| `--set-shuffle SEED` | 设置每脚本字符串表位置混淆的 MSVC 兼容 `rand()` 初始种子。接受十进制或 `0x...` 十六进制。默认：`1`。 |
| `--tmp <tmp_dir>` | 使用指定的持久临时目录。提供此参数后，编译器会在该目录内维护 MD5 缓存（`_md5.json`），从而实现**增量编译**——后续运行时只重编译已更改的 `.ss` 文件。 |
| `--test-shuffle [seed0]` | 穷举搜索所有可能的 32 位 MSVC `rand()` 种子，以找到能精确重建 `<test_dir>` 中字符串表混淆顺序的种子。可选从 `seed0` 开始扫描。 |
| `--gei` | 仅运行 `Gameexe.ini` → `Gameexe.dat` 编译阶段。 |

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

# 仅生成 Gameexe.dat
siglus-ssu -c --gei /path/to/src /path/to/out/

# 强制 UTF-8 编码并禁用加密
siglus-ssu -c --charset utf8 --no-angou /path/to/src /path/to/out/
```

#### 说明

- **自动编码检测：** 若未指定 `--charset`，工具会扫描 `.ss`、`.inc`、`.ini` 文件中的 UTF-8 BOM 或日文字符。找到则使用 `utf-8`，否则使用 `cp932`（Shift-JIS）。
- **增量编译：** 当指定 `--tmp` 时，编译器会缓存所有 `.ss` 和 `.inc` 文件的 MD5 哈希。下次运行时仅重编译已更改（或缺少对应 `.dat`）的文件。若任一 `.inc` 文件发生变化，则触发全量重编译。
- **字符串混淆：** 所有官方游戏都会对每个 `.dat` 文件的字符串表进行位置混淆（只是有些早期作品使用的默认混淆种子为 `1`）。翻译工作**无需**复现此行为——引擎无论字符串顺序如何都能正确读取。`--set-shuffle` 和 `--test-shuffle` 仅在需要逐字节相同的二进制输出时才有用。

---

### `-x` / `--extract` — 提取文件

将 `.pck` 场景文件提取为包含各个 `.ss` 源文本文件的目录（可选附带 `.dat` 反汇编），或从二进制 `Gameexe.dat` 还原 `Gameexe.ini` 明文。

#### 语法

```bash
# 提取 .pck 文件
siglus-ssu -x [--disam] <input_pck> <output_dir>

# 从 Gameexe.dat 还原 Gameexe.ini
siglus-ssu -x --gei <Gameexe.dat | input_dir> [output_dir]
```

#### 参数

| 参数 | 说明 |
|---|---|
| `<input_pck>` | 要提取的 `.pck` 文件路径。 |
| `<output_dir>` | 提取文件的输出目录。提取 `.pck` 时必需供应，但对于 `--gei` 模式是可选的（省略时默认输出在输入文件所在目录）。 |
| `--disam` | 除提取 `.ss` 源文件外，还将每个编译后的 `.dat` 文件的可读反汇编写入 `__DATDIR__` 子目录。不能与 `--gei` 同用。 |
| `--gei` | 不提取 `.pck`，而是将 `Gameexe.dat` 二进制文件解码还原为 `Gameexe.ini` 明文文件。输入参数可以是 `.dat` 文件本身或其父目录。自动检测附近的 `SiglusEngine*.exe` 或 `key.txt` 以推导解密密钥。 |

#### 示例

```bash
# 将 Scene.pck 提取到 translation_work 目录
siglus-ssu -x /path/to/Scene.pck /path/to/translation_work/

# 提取并附带 .dat 反汇编（创建 __DATDIR__ 子文件夹）
siglus-ssu -x --disam /path/to/Scene.pck /path/to/translation_work/

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
siglus-ssu -a [--disam] [--readall] <input_file>

# 比较两个同类型文件
siglus-ssu -a <input_file_1> <input_file_2>

# 从 暗号.dat / SiglusEngine.exe / 目录 分析或推导 exe_el 密钥
siglus-ssu -a <暗号.dat路径 | SiglusEngine.exe路径 | 目录> --angou

# 分析或比较 Gameexe.dat
siglus-ssu -a --gei <Gameexe.dat> [Gameexe.dat_2]
```

#### 参数

| 参数 | 说明 |
|---|---|
| `<input_file>` | 要分析的文件路径。支持扩展名：`.pck`、`.dat`、`.gan`、`.sav`、`.cgm`、`.tcr`。 |
| `[input_file_2]` | 用于结构比较的可选第二个文件。两个文件必须类型相同。 |
| `--disam` | 分析 `.dat` 文件时，将可读反汇编写入 `__DATDIR__` 子目录，而非打印到 stdout。 |
| `--readall` | 仅用于 `read.sav` 文件：将所有已读标志位设为 `1`（标记所有场景为已读）。直接覆盖输入文件。 |
| `--angou` | 将输入解析为 `暗号.dat`（或 `SiglusEngine*.exe`、或包含两者之一的目录），推导并打印 `exe_el` 密钥（`key.txt` 格式的 16 字节密钥）。 |
| `--gei` | 分析或比较 `Gameexe.dat` 文件，而非通用二进制文件。 |

#### 示例

```bash
# 分析 Scene.pck — 打印头部信息、文件数量、加密状态
siglus-ssu -a /path/to/Scene.pck

# 分析编译后的 .dat 脚本 — 打印头部字段和字符串池
siglus-ssu -a /path/to/script.dat

# 比较两个版本的 Scene.pck — 报告文件增删和变化
siglus-ssu -a /path/to/Scene_original.pck /path/to/Scene_translated.pck

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
siglus-ssu -d --c --test-shuffle [skip0] <expected.dbs> <input.csv> <output.dbs>
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

#### CSV 格式

导出的 CSV 使用带 BOM 的 UTF-8 编码和 CRLF 换行，与 Microsoft Excel 兼容。第一行为表头。字符串值中的特殊字符经过转义：

| 转义序列 | 含义 |
|---|---|
| `\\` | 字面反斜杠 |
| `\n` | 换行 |
| `\r` | 回车 |
| `\t` | 制表符 |

---

### `-k` / `--koe` — 按角色收集语音文件

扫描 `.ss` 脚本源文件（或导出的 `.txt` 反汇编文件）中的 `KOE()`、`KOE2()`、`EXKOE()` 语音调用指令，将其与 `.ovk` 语音文件条目匹配，并将对应的 `.ogg` 音频文件提取到按角色命名的子目录中。

同时生成 `koe_master.csv` 清单，列出所有找到的 KOE 条目及其角色名、对话文本和调用位置。

#### 语法

```
siglus-ssu -k <ss_dir> <voice_dir> <output_dir>
```

#### 参数

| 参数 | 说明 |
|---|---|
| `<ss_dir>` | `.ss` 源文件目录，或导出的 `.txt` 反汇编目录（若目录中存在 `.txt` 文件则优先使用）。也可以是单个 `.ss` 或 `.txt` 文件。 |
| `<voice_dir>` | 包含 `.ovk` 语音文件文件的目录（通常命名为 `z0001.ovk`、`z0002.ovk` 等）。也可以是单个 `.ovk` 文件的路径。 |
| `<output_dir>` | 提取的 `.ogg` 文件和 `koe_master.csv` 清单的输出目录。 |

#### 输出结构

```
<output_dir>/
  koe_master.csv           — 所有 KOE 条目的主清单
  <角色名>/               — 每个角色一个子目录
    KOE(000000001).ogg
    KOE(000000002).ogg
    ...
  unreferenced/            — .ovk 中未被任何脚本引用的条目
    KOE(000000003).ogg
    ...
```

#### 示例

```bash
# 从 .ss 脚本收集所有语音文件
siglus-ssu -k /path/to/ss_scripts/ /path/to/voice/ /path/to/voice_out/

# 从单个 .ss 文件收集（用于测试）
siglus-ssu -k /path/to/single_script.ss /path/to/voice/ /path/to/voice_out/
```

#### `koe_master.csv` 格式

| 列名 | 说明 |
|---|---|
| `koe_no` | 全局 KOE 编号（场景号 × 100000 + 条目号）。对于未在 OVK 中找到的调用位置为空。 |
| `character` | 从脚本中 `【名前】` 括号内提取的角色名。 |
| `text` | 从日文引号括号中提取的对话文本。 |
| `callsite` | 分号分隔的 `文件名:行号` 调用位置列表。 |

#### 完成后汇总输出（stderr）

```
=== koe_collector summary ===
OVK entries      : 45,678
OVK files        : 56
...
Audio extracted  : 43,900
CSV path         : /path/to/voice_out/koe_master.csv
```

---

### `-e` / `--exec` — 从指定标签启动引擎

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

工具在引擎可执行文件旁边创建一个临时的 `work_YYYYMMDD` 目录，并以如下参数启动它：

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
| 路径参数 | 单个 `.ss` / `.dat` 文件或目录。**只接受 1 个路径参数**。 |
| `--apply`, `-a` | 将 `.ss.csv` 文本映射就地应用回对应的 `.ss` 文件。`.ss.csv` 必须已与 `.ss` 文件并排存在。 |
| `--disam` | 将已编译的 `.dat` 的字符串列表导出到紧邻 `.dat` 的 `.dat.csv` 文件。支持加密、LZSS 压缩或原始 `.dat`。扫描目录时自动跳过 `Gameexe.dat` 和 `暗号.dat`。 |
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

3. **应用翻译：**

   ```bash
   siglus-ssu -m --apply /path/to/scripts/chapter1.ss
   # 或使用别名
   siglus-ssu -m -a /path/to/scripts/chapter1.ss
   ```

   应用后，工具会自动对修改后的文件执行**括号内容修复**：删除出现在 `【】` 名前括号内的多余双引号和前导空格（这是粘贴翻译文本时的常见问题）。修复数量将报告到 stderr。

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
| `original` | 原始字符串值（转义编码）。 |
| `replacement` | 翻译内容。初始与 `original` 相同，请在此填写翻译。 |

---

### `-g` / `--g00` — 处理 `.g00` 图片文件

提供分析、提取、合并、创建和更新 SiglusEngine `.g00` 图片文件的工具，用于背景、立绘等视觉资源。

#### `.g00` 文件类型

| 类型 | 说明 |
|---|---|
| type0 | LZSS32 压缩的 BGRA（32 位）图片。纯色背景，Alpha 必须为 255。 |
| type1 | LZSS 压缩的调色板图片（最多 256 色）。 |
| type2 | 多 cut 拼合图像 (sprite sheet)，包含多个命名 cut 区域。 |
| type3 | XOR 混淆的 JPEG 图片。 |

> **注意：** 提取和编译 `.g00` 文件需要 [Pillow](https://pillow.readthedocs.io/)（`pip install pillow`）。

#### 语法

```
# 分析 .g00 文件（无需 Pillow）
siglus-ssu -g --a <input_g00>

# 将 .g00 提取为 PNG/JPEG
siglus-ssu -g --x <input_g00 | input_dir> <output_dir>

# 将多个 .g00 文件（或 cut）合并为单张 PNG
siglus-ssu -g --m <input_g00[:cutNNN]> <input_g00[:cutNNN]> [...] --o <output_dir>

# 从图片创建新的 .g00，或基于显式参考 .g00 执行更新
siglus-ssu -g --c [--type N] [--refer <ref_g00 | ref_dir>] <input_png | input_jpeg | input_json | input_dir> [output_g00 | output_dir]
```

#### 参数

| 参数 | 说明 |
|---|---|
| `--a` | **分析**模式。打印类型、画布尺寸、LZSS 统计以及 type2 文件的每个 cut 的详细信息。 |
| `--x` | **提取**模式。解码每个 `.g00` 并写入 PNG 或 JPEG 文件；对于 type2，还会额外导出一份可回灌的 `.type2.json` sidecar。 |
| `--m` | **合并**模式。将多个 `.g00` 图片或 cut 合成为一张 PNG。 |
| `--c` | **创建/更新**模式。不带 `--refer` 时创建新的 `.g00`；带 `--refer` 时，以参考 `.g00` 为 base 更新图片数据。 |
| `--o <output_dir>`, `-o`, `--output`, `--output-dir` | （仅合并模式）合并后 PNG 的输出目录。 |
| `--type N`, `--t N` | （仅创建模式）在创建模式下强制输出 `.g00` 类型；在更新模式下覆盖参考 `.g00` 的预期类型用于验证。 |
| `--refer <ref_g00 | ref_dir>` | （仅创建模式）显式指定更新所用的参考 `.g00`。单文件输入时可传 `.g00` 文件或目录；目录输入时必须传参考目录。 |
| `<g00spec>[:cutNNN]` | 合并模式中，可在路径后附加 `:cutNNN`（如 `bg_day.g00:cut002`）以选择 type2 `.g00` 中的特定 cut。 |

#### 示例

```bash
# 分析 type2 拼合图像
siglus-ssu -g --a /path/to/sprite.g00

# 将目录中所有 .g00 提取为 PNG/JPEG
siglus-ssu -g --x /path/to/g00_dir/ /path/to/png_out/

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

# 直接使用 .type2.json 创建或回灌 type2 .g00
siglus-ssu -g --c --type 2 /path/to/char_face.type2.json /path/to/char_face.g00

# 从包含多份 .type2.json 的目录批量创建 type2 .g00
siglus-ssu -g --c --type 2 /path/to/layout_dir/ /path/to/out_g00/

# 基于显式参考更新现有 .g00
siglus-ssu -g --c /path/to/new_bg.png /path/to/game_bg.g00 --refer /path/to/original_bg.g00

# 使用参考目录进行批量更新
siglus-ssu -g --c /path/to/updated_pngs/ /path/to/out_g00/ --refer /path/to/original_g00/
```

#### 创建模式说明

- 省略 `--refer` 时进入创建模式。
- 当前已实现 **type0**、**type2** 与 **type3** 的创建。
- 默认推断规则：`png` -> type0，`jpg/jpeg` -> type3。创建 type2 时请显式指定 `--type 2` 并直接输入 `.type2.json`。
- 对于 `-g --x` 提取出的多 cut type2，回灌时的创建输入就是自动导出的 `.type2.json`，而不是单张 `*_cutNNN.png`。
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
- `alpha0_rgb` 不再属于推荐 schema。创建器会严格尊重输入 PNG：若 **alpha=0** 像素下方本来就有 hidden RGB，就原样保留；若没有，就不会额外恢复或合成。
- 为兼容旧版自动生成的布局，JSON 中若仍出现 `"alpha0_rgb": "keep"`，当前版本仍接受；除此之外的取值会被拒绝。

#### type2 提取与回灌资产

使用 `-g --x` 提取 type2 `.g00` 时，会固定同时导出 JSON sidecar：
- `单 cut`：`<basename>.png` + `<basename>.type2.json`
- `多 cut`：`<basename>_cut000.png`、`<basename>_cut001.png` ... + `<basename>.type2.json`

说明：
- 提取出的 type2 PNG 会**保留 alpha=0 像素下方的 hidden RGB**。
- 自动生成的 `<basename>.type2.json` 是这组提取资产的标准重建布局。
- 重新创建时，程序会**严格尊重输入 PNG 本身**；不会对 hidden RGB 进行恢复、推断或合成。
- 对于只有一个 cut 的样本，若源 PNG 未被其他软件改写 hidden RGB，则当前实现已经能让 cut block 与原始样本逐字节一致。

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
| `--c` | **创建**模式。将 `.ogg` 文件编码为 `.owp`，或将编号的 `.ogg` 文件组合编码为 `.ovk` 文件。 |
| `--trim <Gameexe.dat>` | （仅提取模式）从 `Gameexe.dat` 读取 `#BGM.*` 循环点表，并用 **ffmpeg** 将每个 `.owp` 裁剪到其循环区域。需要 `ffmpeg` 在系统 PATH 中。 |

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

# 将 .ogg 文件重新编码为 .owp
siglus-ssu -s --c /path/to/translated_ogg/ /path/to/owp_out/
```

#### OVK 创建命名规则

从目录创建 `.ovk` 时，命名为 `<basename>_<N>.ogg`（N 为整数）的文件会被分组打包为单个 `<basename>.ovk`。不带数字后缀的文件单独编码为 `.owp`。

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
| `--a` | **分析**模式。打印详细头部信息，包括外层头字段、TableA 和 TableB 帧元数据。 |
| `--c` | **创建**模式。用 SiglusEngine `.omv` 头包装纯 `.ogv`。 |
| `--refer <ref.omv>` | 从现有的 `.omv` 参考文件复制头部 `mode` 和 TableB `flags_hi24`。若同时指定了 `--mode`/`--flags` 则会被覆盖。 |
| `--mode N` | 覆盖 `mode` 字段（头部偏移 `0x28`）。接受十进制或 `0x...` 十六进制。 |
| `--flags 0xXXXXXX` | 覆盖 TableB `flags` 的高 24 位。接受单个值或逗号分隔的范围规格，如 `0-9:0x1A2B3C00,10-:0x00000000`。 |

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
| `--inplace` | 直接覆盖输入文件，而非写入新路径。 |
| `--lang chs` | 应用内置简体中文预设。 |
| `--lang eng` | 应用内置英文预设。 |
| `--lang <json>` | 应用自定义 JSON 规格的补丁（见下文）。 |

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

# 使用 暗号.dat 推导的密钥原地修改
siglus-ssu -p --altkey /path/to/SiglusEngine.exe /path/to/暗号.dat --inplace

# 应用英文语言补丁
siglus-ssu -p --lang eng /path/to/SiglusEngine.exe

# 原地应用中文语言补丁
siglus-ssu -p --lang chs /path/to/SiglusEngine.exe --inplace

# 应用自定义 JSON 语言补丁
siglus-ssu -p --lang '{"charset":0,"suffix":"ENG","replace":{"Scene.pck":"Scene.eng"}}' /path/to/SiglusEngine.exe
```



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

所有官方游戏都会对每个 `.dat` 文件的字符串表进行位置混淆，只是部分官方使用的 MSVC `rand()` 种子不是默认的 `1`。翻译工作**无需**复现此行为——引擎无论字符串顺序如何，都能正确解析字符串。

若需要逐字节相同的输出，先尝试找到种子：

```bash
siglus-ssu -c --test-shuffle /path/to/src/ /path/to/out/ /path/to/original_dats/
```

若成功找到，使用该种子编译：

```bash
siglus-ssu -c --set-shuffle <找到的种子> /path/to/src/ /path/to/out/
```

> **注意：** 在极少数情况下，单个初始种子可能无法完全逐字节复现位置混淆。这可能是因为原开发者在构建时使用了增量编译（我们也通过 `--tmp` 选项支持），这会改变文件的编译顺序，从而改变 `rand()` 调用的顺序。

### 未安装 Pillow（G00 模式）

G00 图片提取和编译需要 [Pillow](https://pillow.readthedocs.io/)：

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
