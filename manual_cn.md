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
   - [init — 安装/刷新运行时常量](#init--安装刷新运行时常量)
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
   - [-t / --tutorial — 生成静态剧情图](#-t----tutorial--生成静态剧情图)
   - [test — 回编测试](#test--回编测试)
5. [SiglusSceneScript语言规范（简称 SiglusSS语言；以 `-c` 编译器为定义）](#siglusss-language-spec)
6. [提示与故障排除](#提示与故障排除)

---

## 概述

**SiglusSceneScriptUtility**（缩写 **SSSU**，命令名 **siglus-ssu**）是用于操作 **SiglusEngine** 视觉小说引擎所使用文件的命令行工具。它为当前支持的引擎/资源范围实现了一套 SiglusSS 编译流程，并提供了一套完整的工具集：

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

安装后，如果这台机器里还没有通过校验的用户数据 `const.py`，请运行一次 `init` 来安装它：

```bash
siglus-ssu init
```

> **注意：** 需要 Python 3.12 或更高版本。PyPI 同时发布带 Rust 原生扩展的平台 wheel 和通用的 `py3-none-any` 纯 Python 回退 wheel。如果没有兼容的原生 wheel，pip 仍可安装纯 Python wheel；受支持的操作会使用 Python 回退实现，但运行速度可能较慢。只有在该平台上需要原生加速时，才需要配备 Rust 从源码构建。
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

   在当前这个仓库 checkout 中运行时，程序会先查找内置的 `src/siglus_ssu/const.py`，再查找用户数据副本。因此 `uv sync` 完成后通常就可以直接使用。只有在您想安装或刷新用户数据副本，或者当前运行布局不包含这份源码树内置副本时，才需要执行 `uv run siglus-ssu init`：

   ```bash
   uv run siglus-ssu init
   ```

---

## 基本用法

```
siglus-ssu [-h] [-V|--version] [--legacy] [--legacy-full] [--const-profile N] (-lsp|init|-c|-x|-a|-d|-k|-e|-m|-g|-s|-v|-p|-t|test) [参数]
```

### 全局选项

| 选项 | 说明 |
|---|---|
| `-h`, `--help` | 显示帮助信息并退出。 |
| `-V`, `--version` | 显示程序版本并退出。 |
| `--legacy` | 强制使用 Python 编译 backend，但仍保留 LZSS 等 native helper。可用于比较编译行为。 |
| `--legacy-full` | 禁用全部 Rust 原生加速，并在可用处使用纯 Python 回退实现。可用于排查 native 扩展问题。 |
| `--const-profile N` | 选择内置的 `const.py` profile（`0`-`2`，默认 `0`）。只有在目标引擎或编译器变体的 form / element 表与默认 profile 不一致时，才需要改用非默认 profile。不能与 `-c --tmp` 同用。 |

### 命令别名

CLI 也接受几个便利用法：

- `siglus-ssu help` 等同于 `siglus-ssu --help`
- `siglus-ssu version` 等同于 `siglus-ssu --version`
- `siglus-ssu --init ...` 等同于 `siglus-ssu init ...`

### Python 模块 API

本项目只支持 `siglus-ssu` 命令行接口。不支持从外部 Python 代码导入或调用 `siglus_ssu` 模块；内部模块名、函数、全局变量和返回结构都可能变化，且不提供兼容性保证。

### 获取帮助

```bash
# 显示全局帮助，列出所有模式
siglus-ssu --help

# 目前所有模式级 --help 都会回到同一份全局帮助
siglus-ssu -lsp --help

# 其他模式也是一样
siglus-ssu -c --help
```

---

## 模式参考

### `init` — 安装/刷新运行时常量

把包含引擎特定常量（操作码表、密钥推导参数等）的用户数据 `const.py` 安装到本机。只有在该文件缺失，或您显式要求刷新时，`init` 才会从项目 GitHub 仓库下载它。

正常启动时，加载器会先查找源码树里的 `src/siglus_ssu/const.py`，再查找用户数据副本。在当前这个仓库 checkout 中，这份内置文件是存在的，所以即使您执行过 `init`，直接从源码树运行时也仍可能优先使用内置副本。

在使用除 `init` 以外的任何模式前，请先确保至少有一份能通过校验的 `const.py` 会被找到。PyPI 安装依赖用户数据副本，因为 wheel 会排除源码树内置的 `const.py`；而从当前仓库源码树运行时，也可以直接使用内置的 `src/siglus_ssu/const.py`。

#### 语法

```
siglus-ssu init [--force | -f] [--ref <git-ref>]
```

#### 参数

| 参数 | 说明 |
|---|---|
| `--force`, `-f` | 即使用户数据位置已经存在 `const.py`，也强制覆盖。 |
| `--ref <git-ref>` | 指定 `init` 下载 `const.py` 时使用的 Git 分支、标签或提交哈希。如果用户数据目标已经存在文件，请把 `--ref` 与 `--force` 配合使用，才能真正重新下载。默认情况下，`init` 会尝试与当前包版本关联的 ref，包括从 git/GitHub 发现的匹配版本提交，以及类似标签名的 ref。 |

`init` 只有在确实需要获取 `const.py` 时才需要联网访问 GitHub API。若未加 `--force` 且用户数据目标位置已经存在文件，命令会直接复用该文件，不会重复下载，并在后续加载时完成校验。

下载得到的 `const.py` 会与内置的 SHA-512 白名单进行校验。内置的默认 ref 映射跟踪当前支持的包版本；显式传入的 `--ref` 只要最终解析到白名单允许的 `const.py` 内容，仍然可以使用。

#### 示例

```bash
# 确保默认的用户数据 const.py 已安装
siglus-ssu init

# 即使已有 const.py，也重新下载到用户数据位置
siglus-ssu init --force

# 强制从特定标签重新下载 const.py
siglus-ssu init --force --ref v0.4.0
```

---

### `-lsp` — 启动语言服务器

启动面向 **SiglusSceneScript语言**（简称 **SiglusSS语言**）以及 `.inc` 声明文件的标准 **stdio JSON-RPC / Language Server Protocol** 服务。

#### 语法

```
siglus-ssu -lsp [--serial]
```

#### 参数

- `--serial`：禁用默认的 LSP 工作区并行扫描，并强制按串行方式扫描。

#### 说明

- 工作区级别的符号扫描与链接扫描默认并行执行，默认 worker 数为可用 CPU 数的一半。`.inc` 改动会重建目录索引；改动过的 `.ss` 会复用当前 `.inc` 上下文并单独重新扫描。
- 当 Rust 原生扫描器可用时，LSP 工作区扫描与文档符号会自动优先使用 Rust；若原生扫描不可用或不能处理该文档，则回退到 Python 流程。
- 工作区索引会持久化到磁盘并跨会话复用。缓存兼容条件包括目录、`.inc` SHA-256 表、`.ss` 文件集合、程序版本，以及当前 `const.py` 内容/profile。单个 `.ss` 缓存条目只有在该文件 SHA-256 仍匹配时才会复用；未保存的编辑器缓冲区不使用持久索引。默认缓存目录在 Windows 上是 `%LOCALAPPDATA%\siglus_ssu\lsp-index`，在类 Unix 系统上是 `$XDG_CACHE_HOME/siglus_ssu/lsp-index`，否则回退到 `~/.cache/siglus_ssu/lsp-index`；可用 `SIGLUS_SSU_LSP_CACHE_DIR` 覆盖。
- 支持语义 token、push/pull 诊断、自动补全、悬停说明、跳转到定义、查找引用、改名、客户端支持时的准备改名、文档符号，以及同目录未保存 `.inc` 缓冲区对 `.ss` 分析结果的联动刷新。只有客户端支持 `textDocument/diagnostic` 时才声明 pull 诊断。语义 token 分类包括台词文本、system element（系统指令）、角色名，以及已使用/未使用的宏声明。
- 服务会协商 position encoding，返回带范围的补全编辑，按客户端支持的 completion item kind 输出，支持长时间扫描的 work-done progress 取消，并校验文档 URI 与请求结构。
- 分析过程会复用适用的 `-c` 阶段（`CA`、`LA`、`SA`、`MA`、`BS`）。项目模型按目录组织，与 `.inc` / `.ss` 联合分析及全局 `.inc #command` 链接一致。

---

### `-c` / `--compile` — 编译脚本

将一个目录中的 `.ss` SceneScript 源文件编译为 `.pck` 文件。编译过程中会先在临时目录生成各个场景的 `.dat`，然后在常规模式下再将它们链接并打包为最终的 `Scene.pck`。编译流程实现当前支持的 SiglusEngine 风格构建阶段，包括 LZSS 压缩、每脚本字符串表乱序、以及基于 `暗号.dat` 的加密。

默认情况下，编译模式会在 Rust 原生 backend 可用且支持当前选项时优先使用 Rust，否则自动回退到 Python backend。全局 `--legacy` 强制使用 Python 编译 backend，但仍允许 LZSS 等 native helper；`--legacy-full` 会禁用全部 Rust 原生加速。

未指定 `--tmp` 时，每次编译都会创建名称唯一的自动临时目录。因此，即使多个编译同时写入同一输出目录，也不会共享中间文件。

链接场景写入 `.pck` 时，场景名采用与官方编译器一致的 ASCII-only 小写规则：仅 `A` 至 `Z` 会变为 `a` 至 `z`，非 ASCII 字符不会大小写折叠，包括 `ＥＤ` 这类全角拉丁字母。

编译后的 `.dat` payload 在 `.pck` 内不保留独立文件名；每个 payload 都通过规范化后的场景名寻址，因此场景查找对 ASCII 大小写不敏感。嵌入 Original Source 区域的 `.ss` 和 `.inc` 条目会保留源文件名拼写，但这些名称只是归档元数据，不是运行时场景键。运行时读取输入文件或目录时优先使用精确名称；在所有平台上，精确路径不存在时都会按 Windows 文件名大小写规则回退匹配，并拒绝多义结果。每次枚举目录都会拒绝 `A.ss` 与 `a.ss` 这类按 Windows 文件名小写规则发生碰撞的直接子项。创建输出时仍遵循目标文件系统的原生路径语义。

也支持通过 `--gei` 单独编译 `Gameexe.ini` → `Gameexe.dat`。

#### 语法

```
# 标准编译
siglus-ssu -c [选项] <input_dir> <output_pck | output_dir>

# 仅从现有 Gameexe.ini 编译 Gameexe.dat
siglus-ssu -c --gei <input_dir | Gameexe.ini> <output_dir>

# 编译并穷举搜索混淆种子
siglus-ssu -c --test-shuffle [seed0] [--csv <seed_csv>] <input_dir> <output_pck | output_dir> <test_dir>
```

#### 参数

| 参数 | 说明 |
|---|---|
| `<input_dir>` | 包含 `.ss` 源文件的目录，可选包含 `.inc`、`.ini` / `Gameexe.ini`、`暗号.dat`。 |
| `<output_pck \| output_dir>` | 输出路径。若参数指向一个已存在目录，则在其中创建 `Scene.pck`。否则该参数会按输出文件路径处理；即使一个不存在的路径不以 `.pck` 结尾，也会按这个精确文件名写出。 |
| `--debug` | 编译后保留中间临时文件（`.dat`、`.lzss` 等）。不能与 `--tmp` 同用。 |
| `--charset ENC` | 用 Python 当前可用的任意 codec 强制指定整个项目的源文件编码。CP932/Shift-JIS 别名（`jis`、`sjis`、`shift_jis`、`shift-jis`、`cp932`、`ms932`、`windows-932`、`windows932`）有意统一为 Windows CP932；同时接受 UTF-8 别名。省略时，每个文件仅在 UTF-8 与 CP932 之间自动检测。 |
| `--no-os` | 跳过 OS（原始 source）嵌入阶段。仍会正常生成并写出 `Scene.pck`，只是包内不再附带原始 source；不影响脚本本身的加密或压缩。 |
| `--dat-repack` | 不编译 `.ss` 脚本，而是扫描 `input_dir` 当前层现有的 Siglus 场景 `.dat` 文件，将它们复制后直接打包成一个 `.pck` 文件。这对于打包已经编译好的脚本非常有用。它只能与 `--no-os` 和/或 `--no-lzss` 组合使用。不能与 `--tmp` 或 `--test-shuffle` 同用。 |
| `--no-angou` | 禁用 LZSS 压缩和 XOR 加密，将 `scn_data_exe_angou_mod = 0`，并且不嵌入原始 source。不能与 `--tmp` 同用。 |
| `--no-lzss` | 禁用 LZSS 阶段，同时保留脚本原有的加密与头部行为。此模式不嵌入原始 source chunk，对应官方的“easy link”式输出。不能与 `--tmp` 同用。 |
| `--serial` | 禁用多进程并行编译，并强制编译阶段按串行方式运行。默认启用并行编译。 |
| `--max-workers N` | 最大并行工作进程数。仅在启用并行编译时生效；默认为自动。 |
| `--set-shuffle SEED` | 设置每脚本字符串表位置混淆的 MSVC 兼容 `rand()` 初始种子。接受十进制或 `0x...` 十六进制。默认：`1`。启用时等同于隐式带上 `--serial`。不能与 `--tmp` 同用。 |
| `--tmp <tmp_dir>` | 使用指定的持久临时目录。提供此参数后，编译器会在该目录内维护 SHA-256 缓存（`_source_hashes.json`），从而实现**增量编译**——后续运行时只重编译已更改的 `.ss` 文件。该缓存仅允许单写者；并发编译若使用同一目录会被拒绝。不能与 `--debug`、`--dat-repack`、`--no-angou`、`--no-lzss`、`--set-shuffle`、`--test-shuffle`、`--csv`、`--gei` 或全局 `--const-profile` 同用。 |
| `--test-shuffle [seed0]` | 从 `seed0`（默认 `0`）扫描到 `0xFFFFFFFF`，寻找能复现 `<test_dir>` 中第一个 scene 字符串表顺序的 32 位 MSVC `rand()` 种子，再用全部 scene 验证该种子。不能与 `--tmp` 同用。 |
| `--csv <seed_csv>` | 与 `--test-shuffle` 同用时，写出 CSV，记录串行重建阶段每个场景对象的初态种子和终态种子。若路径是已存在目录或以路径分隔符结尾，则在其中写出 `test_shuffle_seeds.csv`。不能与 `--tmp` 同用。 |
| `--gei` | 仅运行 `Gameexe.ini` → `Gameexe.dat` 编译阶段。输出参数始终按目录处理；如果目录不存在会自动创建，并在其中写入 `Gameexe.dat`。不能与 `--tmp` 同用。 |

#### 编译统计

编译器会在编译结束前打印一段 `=== Compiling Stats ===` 汇总。

其中包含：

- 本次实际运行过的阶段耗时总计（如 `GEI`、`IA`、`CA`、`LA`、`SA`、`MA`、`BS`、`Compiling`）
- `inc_files`：参与编译的 `.inc` 文件数量
- `scene_files`：输入目录中的 `.ss` 文件总数
- `compiled_scene_files`：本次实际参与编译的 `.ss` 文件数量；在增量编译时，这里就是增量子集

当本次运行完成普通的全量 scene 编译时，汇总中还会追加项目级详细统计：

- `#replace`、`#define`、`#define_s`、`#macro` 的总数与未使用数
- `read_flags` 与 `read_flags_scenes`
- scene-local `#property` / `#command`、预处理指令、`#inc_start` 区块、label、语句、表达式、运算符种类、字符串池与台词行等 source 侧统计
- `binary_sizes`
- 最后统一打印的 `top5_*` 明细：`top5_read_flags_scenes`、`top5_string_pool_scenes`、`top5_dat_scenes`

当本次运行不是普通的全量 scene 编译时，项目级详细统计会直接省略，不再打印 `n/a` 占位。这包括 `--tmp`、`--dat-repack`、`--test-shuffle`、`--gei`、没有 `.ss` 输入，以及部分编译或编译失败等情况。对应阶段实际运行过时，基础的耗时与文件数汇总仍会保留。

#### 示例

```bash
# 将翻译目录编译为新的 Scene.pck
siglus-ssu -c /path/to/translation_work /path/to/Scene_translated.pck

# 使用默认并行工作进程编译，并保留临时文件供检查
siglus-ssu -c --debug /path/to/src /path/to/out/

# 强制串行编译
siglus-ssu -c --serial /path/to/src /path/to/Scene.pck

# 增量编译：只重编译已更改的 .ss 文件
siglus-ssu -c --tmp /path/to/cache /path/to/src /path/to/Scene.pck

# 使用指定乱序种子编译（逐字节匹配官方输出）
siglus-ssu -c --set-shuffle 12345 /path/to/src /path/to/Scene.pck

# 从 12345 开始穷举搜索混淆种子
siglus-ssu -c --test-shuffle 12345 /path/to/src /path/to/out/ /path/to/original_dats/

# 穷举搜索混淆种子，并写出每个场景的初态/终态种子
siglus-ssu -c --test-shuffle 12345 --csv /path/to/seeds.csv /path/to/src /path/to/out/ /path/to/original_dats/

# 将现有 .dat 文件直接重新打包
siglus-ssu -c --dat-repack /path/to/dat_dir /path/to/Scene_repacked.pck

# 将现有 .dat 文件直接重新打包，并且不做 LZSS
siglus-ssu -c --dat-repack --no-lzss /path/to/dat_dir /path/to/Scene_repacked.pck

# 仅从现有 Gameexe.ini 生成 Gameexe.dat
siglus-ssu -c --gei /path/to/src /path/to/out/

# 强制 UTF-8 编码并禁用加密
siglus-ssu -c --charset utf8 --no-angou /path/to/src /path/to/out/
```

#### 说明

- **源文件解码：** 若未指定 `--charset`，每个源文件都会独立尝试 UTF-8 与 CP932，并根据 BOM、严格解码结果和确定性的歧义评分选择编码。其他 Python codec 必须显式指定，并采用严格解码；非法字节序列会令编译失败。解码会移除一个开头的 Unicode BOM，并把 CRLF 或孤立 CR 归一化为 LF，但不会进行 Unicode 规范化。两个编译后端接收同一份解码后的文本快照。
- **与编码无关的编译：** 源文件编码不会选择另一套词法规则。解码完成后，CP932、UTF-8 和其他编码都使用与官方日文编译器一致、固定的 CP932 双字节字符分类。因此，内容等价的 CP932 与 UTF-8 源文件会得到相同编译结果。固定集合以外的字符可以写在引号字符串内，但不会被当作无引号的全角文本。
- **增量编译：** 当指定 `--tmp` 时，编译器会缓存所有 `.ss` 和 `.inc` 文件的 SHA-256 哈希。缓存兼容条件包括 `siglus-ssu` 版本、源码字符集以及当前 `const.py` 内容/profile。下次兼容运行时仅重编译已更改（或缺少对应 `.dat`）的文件，并复用已有 `.lzss` 产物。若某个场景源码发生变化，或对应 `.lzss` 缺失，则重新生成该场景的 `.lzss`。若任一 `.inc` 文件发生变化，则触发全量重编译。
- **字符串混淆：** 编译器会用 MSVC 兼容 `rand()` 种子打乱每个 `.dat` 的字符串表；字符串顺序不影响普通翻译工作。`--test-shuffle` 根据第一个 scene 寻找种子，再串行重建全部 scene；后续若有不匹配仍会生成请求的输出，但命令返回失败。已知种子可通过 `--set-shuffle` 使用。

---

### `-x` / `--extract` — 提取文件

将 `.pck` 场景文件提取为一个带时间戳的目录，目录内包含已解码的场景 `.dat` 文件以及包内嵌入的原始 source 文件；或者从二进制 `Gameexe.dat` 还原 `Gameexe.ini` 明文。

#### 语法

```bash
# 提取 .pck 文件
siglus-ssu -x [--disam|--decompile] <input_pck> [output_dir] [--angou <path|angou=text|key=bytes>]

# 对目录中的 `.dat` 批量反汇编
siglus-ssu -x --disam <input_dir> [output_dir] [--angou <path|angou=text|key=bytes>]

# 从 Gameexe.dat 还原 Gameexe.ini
siglus-ssu -x --gei <Gameexe.dat | input_dir> [output_dir] [--angou <path|angou=text|key=bytes>]
```

#### 参数

| 参数 | 说明 |
|---|---|
| `<input_pck>` | 要提取的 `.pck` 文件路径。 |
| `<input_dir>` | 启用 `--disam` 时，用来扫描 `.dat` 的目录路径。只处理该目录当前层的 `.dat` 文件。 |
| `<output_dir>` | 提取文件的输出目录。对所有 `-x` 模式都可省略；省略时默认输出到输入文件所在目录，若输入本身是目录，则默认输出到该目录。 |
| `--disam` | 对 `.pck` 输入时，额外写出 `<scene>.dat.txt` 反汇编。对目录输入时，只扫描该目录当前层的 `.dat`，并将 `.dat.txt` 写入 `<output_dir>`。不能与 `--gei` 同用。非场景 `.dat` 会自动跳过。 |
| `--decompile` | 对完整 `.pck` 输入执行与 `--disam` 相同的反汇编流程，并额外写出重建后的 `decompiled/<scene>.ss` 以及 `decompiled/__decompiled.inc`。单个 `.dat` 文件和 `.dat` 目录不支持该选项。不能与 `--gei` 同用。 |
| `--angou <path\|angou=text\|key=bytes>` | 覆盖或补充场景/Gameexe 解密 key 来源。使用 [`-a` / `--analyze`](#-a----analyze--分析和比较文件) 中说明的公共 key-source 规则。 |
| `--gei` | 不提取 `.pck`，而是将 `Gameexe.dat` 二进制文件解码还原为 `Gameexe.ini` 明文文件。输入参数可以是 `.dat` 文件本身或其父目录。key 候选会按公共 key-source 规则尝试。 |

对 `.pck` 输入时，实际输出会写入 `output_YYYYMMDD_HHMMSS/` 目录。若包内存在原始 source，会与解码后的场景 `.dat` 一起还原出来。启用 `--disam` 时，命令结束前会打印反汇编总耗时；启用 `--decompile` 时，还会打印 hints 和反编译两个阶段的总耗时。

当前 decompiler 属于实验性质。`--decompile` 输出的 `decompiled/*.ss` 更适合拿来阅读和排查，不应视为对原始 source 的可靠还原，也不应默认当作稳定可回编的发布输入。

#### 示例

```bash
# 将 Scene.pck 提取到 translation_work 目录
siglus-ssu -x /path/to/Scene.pck /path/to/translation_work/

# 将 Scene.pck 提取到输入文件同目录
siglus-ssu -x /path/to/Scene.pck

# 提取并附带 `.dat` 反汇编
siglus-ssu -x --disam /path/to/Scene.pck /path/to/translation_work/

# 提取并附带 `.dat` 反汇编和反编译 `.ss`
siglus-ssu -x --decompile /path/to/Scene.pck /path/to/translation_work/

# 使用显式 key 来源提取加密场景
siglus-ssu -x /path/to/Scene.pck /path/to/translation_work/ --angou /path/to/game_dir/

# 对单个目录当前层的 `.dat` 批量反汇编
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
# 分析 .pck 文件
siglus-ssu -a <input_file.pck> [--angou <path|angou=text|key=bytes>]

# 分析 .dat 文件
siglus-ssu -a [--disam] <input_file.dat> [--angou <path|angou=text|key=bytes>]

# 分析或修改其他支持文件
siglus-ssu -a [--readall|--apply] <input_file.sav>
siglus-ssu -a <input_file.(gan|sav|cgm|tcr)>

# 仅统计 .pck 中的台词计数并导出逐文件 CSV
siglus-ssu -a --word <input_pck> [output_csv] [--angou <path|angou=text|key=bytes>]

# 比较两个 .pck 文件
siglus-ssu -a [--payload] <input_file_1.pck> <input_file_2.pck> [--angou <path|angou=text|key=bytes>]

# 比较两个 .dat 文件
siglus-ssu -a [--payload] [--disam] <input_file_1.dat> <input_file_2.dat> [--angou <path|angou=text|key=bytes>]

# 不显式指定 key 来源时比较两个文件
siglus-ssu -a <input_file_1> <input_file_2>

# 从 key 来源分析或推导 exe_el 密钥
siglus-ssu -a --angou <path|angou=text|key=bytes>

# 分析或比较 Gameexe.dat
siglus-ssu -a --gei <Gameexe.dat> [Gameexe.dat_2] [--angou <path|angou=text|key=bytes>]
```

#### 参数

| 参数 | 说明 |
|---|---|
| `<input_file>` | 要分析的文件路径。支持扩展名：`.pck`、`.dat`、`.gan`、`.sav`、`.cgm`、`.tcr`。分析或比较 `.pck` 时，若可读取内嵌 `.ss` original source chunk，会在原有表格中以 `ID` 列显示其中的 `SCENE_SCRIPT_ID`；比较 `.pck` 时，source ID 也会作为比较对象。 |
| `[input_file_2]` | 用于比较的可选第二个文件。若两个文件类型相同，则执行结构比较；若类型不同，则退化为分别分析两个文件。 |
| `--disam` | 分析 `.dat` 文件或比较两个 `.dat` 文件时，将可读反汇编写在各自输入 `.dat` 同目录下的 `<scene>.dat.txt`。命令结束前会打印反汇编总耗时。如需重建 `.ss` 输出，请使用 `-x --decompile <input_pck>`。 |
| `--readall` | 只允许用于 `read.sav` 和 `global.sav`。对 `read.sav`：将所有已读标志位设为 `1`（标记所有场景为已读）。对 `global.sav`：就地解锁引擎管理的收集字段，目前包括存在时的 `cg_table`、`bgm_table` 和 `chrkoe.look_flag`。写入前会自动创建不覆盖旧文件的 `.bak` 备份。不能与 `--apply`、比较模式、`--disam`、`--payload`、`--word`、`--angou` 或 `--gei` 同用。不会修改无关的通用全局标志数组，也不会修改 Steam 这类外部成就后端。 |
| `--apply` | 仅用于 `global.sav`：读取同目录、同主文件名的 `global.txt`，应用其中可编辑的 `G[n]`、`Z[n]`、`cg_table[n]`、`bgm_table[n]` 和 `chrkoe[n].look_flag` 条目，自动创建不覆盖旧文件的 `.bak` 备份，并就地重写 `.sav`。其他生成字段，如 `M`、`global_namae` 和角色显示名，会被忽略。不能与 `--readall`、比较模式、`--disam`、`--payload`、`--word`、`--angou` 或 `--gei` 同用。 |
| `--word` | 仅用于 `.pck`：跳过常规结构分析，统计每个已解码场景 `.dat` 和每个内嵌 `.ss` source 的台词计数，逐文件打印，并写入 CSV。若省略 `[output_csv]`，则默认写到输入 `.pck` 同目录下的 `<input_pck_stem>.word.csv`；若 `[output_csv]` 是已存在目录或以路径分隔符结尾，则把这个默认 CSV 文件名写入该目录。可以与 `--angou` 同用。 |
| `--payload` | **（仅比较模式）** 对 `.pck` 和 `.dat` 的比较额外执行规范化场景运行时语义比较，覆盖解码/解压后的 `scn_bytes`、有效控制流目标、场景属性布局、姓名/已读标志表，以及包级属性和命令路由元数据。字符串池 shuffle 的全部影响都会被规范化，包括 `str_id` 变化和依赖 shuffle 的 `namae_list` 去重结果；未使用且以零填充的 z-label 容量也会被忽略。说话人文本仍由规范化后的 `CD_NAME` 事件和逻辑姓名表覆盖。`.pck` 结果会区分 `same`、仅解析文本变化的 `text_only`、非文本运行时差异的 `real_diff`，以及 payload 比较不可用时的 `-`；`.dat` 结果使用 `identical`、`text_only`、`real_diff` 或 `unavailable`。当 Rust 原生 payload scanner 可用时会自动使用 Rust，否则回退到 Python。它比普通结构比较更耗时，但能更好地区分纯翻译文本变化与真实场景行为变化。 |
| `--angou <path\|angou=text\|key=bytes>` | `.pck`/`.dat` 分析、`.pck` 台词统计、`Gameexe.dat` 分析或单独推导 key 时使用的显式 key 来源。`--angou` 必须是命令中的最后一个选项，必须使用 `--angou VALUE` 的分离写法，且值不能为空。裸值一律视为文件或目录路径；`暗号.dat` 字面量请写成 `angou=text`，16 字节 `exe_el` key 字面量请写成 `key=bytes`，例如 `key=0xA9,0x86,...`。解密时会按顺序尝试候选：显式 `--angou`；输入 `.pck` 内嵌 `暗号.dat`；当前目录；父目录。只有高优先级来源已经解析出 key、但该 key 未通过解密校验时，才会回落到低优先级候选；缺失、格式错误或无法产出 key 的显式来源会作为输入错误报告。若 `--angou` 使用裸路径，则本次请求禁用父目录探测，回落到当前目录后停止。目录探测不递归。每个被探测目录内部顺序为 `Scene.pck`、`Scene*.pck`、`暗号.dat`、`key.txt`、`SiglusEngine*.exe`。 |
| `--gei` | 分析或比较 `Gameexe.dat` 文件，而非通用二进制文件。该模式可以使用 `--angou`，但会拒绝其他 analyze 修饰选项，例如 `--disam`、`--readall`、`--apply`、`--payload` 和 `--word`。 |

尝试解密候选时会向 stderr 打印 key-source 诊断信息：每行包含来源、类型、适用时的路径或包内文件、具体 `exe_el` 值，以及该候选是 accepted 还是 rejected 并继续 fallback。

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

# 使用目录 key 来源分析加密 .dat 脚本
siglus-ssu -a /path/to/script.dat --angou /path/to/game_dir/

# 比较两个版本的 Scene.pck — 报告文件增删和变化
siglus-ssu -a /path/to/Scene_original.pck /path/to/Scene_translated.pck

# 比较两个 Scene.pck 的规范化场景运行时语义
siglus-ssu -a --payload /path/to/Scene_original.pck /path/to/Scene_translated.pck

# 将 .dat 反汇编写入磁盘以供检查
siglus-ssu -a --disam /path/to/script.dat

# 将 read.sav 中的所有已读标志设为 1
siglus-ssu -a --readall /path/to/savedata/read.sav

# 解锁 global.sav 中由引擎管理的收集标志
siglus-ssu -a --readall /path/to/savedata/global.sav

# 生成 global.txt，手动编辑后，再把支持的值写回 global.sav
siglus-ssu -a /path/to/savedata/global.sav
siglus-ssu -a --apply /path/to/savedata/global.sav

# 从 暗号.dat 推导 exe_el 密钥
siglus-ssu -a --angou /path/to/暗号.dat

# 直接从暗号字符串推导 exe_el 密钥
siglus-ssu -a --angou "angou=literal_angou_string"

# 直接从 SiglusEngine 可执行文件推导 exe_el 密钥
siglus-ssu -a --angou /path/to/SiglusEngine.exe

# 从 16 字节 key 字面量推导 exe_el 密钥
siglus-ssu -a --angou "key=0xA9,0x86,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00"

# 从游戏目录推导 exe_el 密钥
siglus-ssu -a --angou /path/to/game_dir/
```

#### 输出格式（`.pck` 示例）

```
==== Analyze ====
file: /path/to/Scene.pck
type: pck
size: 123456789 bytes (0x75BCD15)
mtime: 2024-01-01 12:00:00
sha256: a1b2c3d4...

header:
  header_size=...
  scn_data_exe_angou_mod=...
  original_source_header_size=...
counts:
  inc_prop=...  inc_cmd=...
  scn_name=...  scn_data_index=...  scn_data_cnt=...
read_flags: ...
read_flags_scenes: ...
top5_read_flags_scenes: scene_a(...), scene_b(...), ...
...
```

如果能找到内嵌或相邻的 `暗号.dat`，`.pck` 分析还会在末尾追加一个 `=== 暗号.dat ===` 区块，并打印它的第一行，风格与编译模式的汇总输出一致。

#### 字数统计输出（`-a --word`）

`-a --word` 会为每个已解码场景 `.dat` 和每个内嵌 `.ss` source 打印一行，并写出同内容的 CSV。计数规则如下：

- 汉字、平假名、全角/独立片假名、注音符号每个字符算 `1`；半角片假名基字符后接半角浊音/半浊音标记时，两者合计为一个单位
- 韩文按连续词段计数
- 其他字母和数字按连续词段计数
- 内部的 `'`、`’`、`-`、`_`、`‐`、`‑`、`﹣`、`－` 在两侧最近的非组合标记字符都是韩文、非 CJK 字母或数字时，不拆分同一词段
- 数字段中，内部的 `.`、`,`、`/`、`:` 及其全角变体，在两侧都是十进制数字时不拆分
- 标点、空白、emoji 以及其他符号算 `0`

CSV 列为：

- `type` — `dat` 或 `ss`
- `path` — `.pck` 内的逐文件相对路径
- `status` — `ok` 或 `failed`
- `dialogue_lines` — 计入统计的台词条目数
- `dialogue_count` — 计入统计的台词总计数

---

### `-d` / `--db` — 导出和编译 `.dbs` 数据库

处理以表格形式存储引擎数据的 `.dbs` 二进制数据库文件。

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
siglus-ssu -d --c [--type N] [--set-shuffle SEED] --test-shuffle [skip0] <expected.dbs> <input_csv> <output_dbs | output_dir>
```

#### 参数

| 参数 | 说明 |
|---|---|
| `--x` | **提取**模式：导出 `.dbs` → `.csv`。 |
| `--a` | **分析**模式：转储结构信息。提供两个参数时比较两个 `.dbs` 文件。 |
| `--c` | **编译**模式：从 `.csv` 创建 `.dbs`。 |
| `--type N` | 覆盖生成的 `.dbs` 的 `m_type` 字段（整数）。默认：`1`。 |
| `--set-shuffle SEED` | 设置打包前追加的随机 padding 字节所使用的 MSVC `rand()` 初始种子。接受十进制或 `0x...` 十六进制。默认：`1`。 |
| `--test-shuffle [skip0]` | 从 `skip0`（默认 `0`）开始搜索最多 16,777,216 个 MSVC `rand()` 跳过量，以匹配参考 `.dbs` 尾部的 padding pattern。仅支持单文件模式。 |

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

编译 `m_type=0` 时，每个字符串都必须能严格编码为 Shift-JIS；其他类型使用严格 UTF-16LE 编码。无法编码的单元格会报告 CSV 路径、记录起始行、列和 call number，且不会写出无效 `.dbs`。

#### CSV 格式

导出的 CSV 使用带 BOM 的 UTF-8 编码和 CRLF 换行，与 Microsoft Excel 兼容。文件前两行为 `#DATANO` 和 `#DATATYPE` 头行，之后才是数据行。

- `#DATANO` 行：首列固定为 `#DATANO`，其余各列是列头的 call number。
- `#DATATYPE` 行：首列固定为 `#DATATYPE`，其余各列是对应列的数据类型标记；当前主要会看到 `S`（字符串）和 `V`（数值/其他 32 位单元）。
- 数据行：每行首列是该行的 row call number，其余各列按前两行定义的列顺序对应。

字符串值中的特殊字符由标准 CSV quoting 处理，而不是使用额外的反斜杠转义层：

| 字符 | CSV 处理方式 |
|---|---|
| `\` | 字面反斜杠；不是转义前缀。 |
| `"` | 需要时由 CSV quoting 写成双引号转义。 |
| 换行 / 回车 | 作为实际换行字符保存在带引号的 CSV 字段中。 |
| TAB | 作为实际制表符保存。 |

---

### `-k` / `--koe` — 按角色收集语音文件

扫描 `.pck`、单个场景 `.dat`，或场景 `.dat` 目录树中的编译后场景数据，从反汇编 trace 中读取 KOE 相关调用，将其与 `.ovk` 语音文件条目匹配，并提取对应的 `.ogg` 音频文件。普通模式下，输出会按角色名分类到子目录中。

普通模式下还会生成 `koe_master.csv` 清单，列出所有找到的 KOE 条目及其角色名、对话文本和调用位置。如果同一个 `koe_no` 被多个不同的角色/文本组合引用，CSV 会保留多行，并且只在相同 `koe_no`/角色/文本组合内合并调用位置。若直接扫描 `.pck`，调用位置会写成 `Scene.pck!scene.dat:line`。命令处理完成后还会统计**已引用语音**的总时长；写入 `unreferenced/` 的条目不会计入该总时长。若某个 `.ogg` 的时长读取失败，也不会阻止 CSV 导出，但会计入 `Duration failed` 统计。

#### 语法

```
siglus-ssu -k [--stats-only] <scene_input> <voice_dir> <output_dir> [--angou <path|angou=text|key=bytes>]
siglus-ssu -k [--stats-only] --single KOE_NO <voice_dir> <output_dir>
```

#### 参数

| 参数 | 说明 |
|---|---|
| `<scene_input>` | `Scene.pck`、单个场景 `.dat` 文件，或场景 `.dat` 目录树的路径。普通模式必填；使用 `--single` 时不需要。 |
| `<voice_dir>` | 包含 `.ovk` 语音文件的扁平顶层目录（通常命名为 `z0001.ovk`、`z0002.ovk` 等）。也可以是单个 `.ovk` 文件的路径。目录模式当前只扫描该目录当前层的 `.ovk` 文件，不递归，也不会进入角色子目录。 |
| `<output_dir>` | 提取的 `.ogg` 文件输出目录。普通模式下还会在这里写出 `koe_master.csv`；使用 `--single` 时，提取出的单个文件会直接写到 `<output_dir>` 根下。 |
| `--angou <path\|angou=text\|key=bytes>` | 扫描加密 `Scene.pck` 或场景 `.dat` 输入时使用的 key 来源。使用 [`-a` / `--analyze`](#-a----analyze--分析和比较文件) 中说明的公共 key-source 规则。不能与 `--single` 同用。 |
| `--stats-only` | 打印汇总，但不会写任何 `.ogg` 文件。普通模式下仍会写出 `koe_master.csv`；若同时使用 `--single`，则不会写 CSV。 |
| `--single KOE_NO` | 仅提取指定的全局 KOE 编号。此模式下不需要场景输入，不会生成 `koe_master.csv`，不会创建角色名或 `unreferenced` 子目录，输出文件会直接写成 `<output_dir>/KOE(XXXXXXXXX).ogg`。 |

#### 输出结构

```
<output_dir>/
  koe_master.csv           — 所有 KOE 条目的主清单
  <角色名或 %EMPTY>/     — 每个角色一个子目录；无法推断角色名时使用 %EMPTY
    KOE(000000001).ogg
    KOE(000000002).ogg
    ...
  unreferenced/            — .ovk 中未被任何已扫描场景引用的条目
    KOE(000000003).ogg
    ...
```

角色名用作目录段时会进行百分号转义，但 `koe_master.csv` 中仍保留原始值。路径分隔符、控制字符、Windows 非法字符、字面 `%`、末尾空格或点、保留设备名以及工具固定输出名会分别编码，而不会统一折叠成同一个替代字符。仅大小写不同的名称仍遵循目标文件系统的大小写敏感规则。

使用 `--single` 时，输出结构变为：

```
<output_dir>/
  KOE(123456789).ogg
```

#### 示例

```bash
# 直接从 Scene.pck 收集所有语音文件
siglus-ssu -k /path/to/Scene.pck /path/to/voice/ /path/to/voice_out/

# 使用显式 key 来源扫描加密场景数据
siglus-ssu -k /path/to/Scene.pck /path/to/voice/ /path/to/voice_out/ --angou /path/to/game_dir/

# 从解码后的场景 `.dat` 目录收集
siglus-ssu -k /path/to/scene_dir/ /path/to/voice/ /path/to/voice_out/

# 从单个场景 `.dat` 文件收集
siglus-ssu -k /path/to/chapter1.dat /path/to/voice/ /path/to/voice_out/

# 只生成 CSV 和汇总，不写任何 `.ogg`
siglus-ssu -k --stats-only /path/to/Scene.pck /path/to/voice/ /path/to/voice_out/

# 只提取一个全局 KOE 条目
siglus-ssu -k --single 123456789 /path/to/voice/ /path/to/voice_out/
```

#### `koe_master.csv` 格式（仅普通模式）

| 列名 | 说明 |
|---|---|
| `koe_no` | 全局 KOE 编号（场景号 × 100000 + 条目号）。只要调用位置中能解析出编号，即使未在 OVK 中找到也会保留。若某个 KOE 被多个不同角色/文本组合引用，同一编号可能出现多行。 |
| `character` | 从 scene trace 中的 `CD_NAME` 事件和行内语音元数据推断出的角色名。 |
| `text` | 从 scene trace 中的 `CD_TEXT` 事件和行内语音元数据推断出的文本。 |
| `duration_sec` | 语音时长，单位为秒，由 OVK 条目的 sample count 和 Ogg 采样率换算得出。若无法读取 OVK 条目或时长元数据，则为空。 |
| `callsite` | 分号分隔的当前 KOE/文本行的 `filename:line`（文件名:行号）调用位置列表；若直接扫描 `.pck`，则为 `Scene.pck!scene.dat:line`。 |

#### 完成后汇总输出（stderr）

完成后，汇总会输出到 stderr：

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
KOE multi-text   : 3
KOE multi-text no: 200259, 2300267, 30100310
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

上面的示例是普通模式输出。`Stats only` 和 `Single KOE` 仅在使用对应选项时出现。`KOE multi-text` 统计关联到多个非空对话文本的 `koe_no`，`KOE multi-text no` 会列出这些编号。这个列表基于 OVK 匹配前的场景引用计算；未在 OVK 中找到的调用在 CSV 中仍会保留已知的 `koe_no`。使用 `--single` 时，不会显示场景扫描相关行，也不会显示 CSV 相关行。

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

将已编译场景 `.dat` 的字符串表导出为 CSV 文本映射，并把译文应用回已编译文件。工具有意不修改 `.ss` 源文件，因为项目宏和替换规则可能令源代码层面的字符串修改改变编译结构。

#### 语法

```
# 从已编译的 .dat 文件导出字符串列表
siglus-ssu -m <path_to_dat | path_to_dir> [--angou <path|angou=text|key=bytes>]

# 将已翻译的字符串列表应用回已编译的 .dat 文件
siglus-ssu -m --apply <path_to_dat | path_to_dir> [--angou <path|angou=text|key=bytes>]
```

#### 参数

| 参数 | 说明 |
|---|---|
| `<path_to_dat \| path_to_dir>` | 单个场景 `.dat` 文件或目录。**只接受 1 个路径参数**。目录输入会递归扫描。 |
| `--apply` | 将 `.dat.csv` 中的译文就地应用回已编译的 `.dat`。不带此选项时，将字符串列表导出到紧邻 `.dat` 的 `.dat.csv`。导出与应用都支持加密、LZSS 压缩或原始 `.dat`；扫描目录时会递归处理 `.dat`，并自动跳过 `Gameexe.dat` 和 `暗号.dat`。 |
| `--angou <path\|angou=text\|key=bytes>` | 加密 `.dat` 使用的 key 来源。使用 [`-a` / `--analyze`](#-a----analyze--分析和比较文件) 中说明的公共 key-source 规则。输入为目录时，会先为该目录解析一次 key 候选，并复用于扫描到的每个 `.dat` 文件。 |

#### 工作流程

1. **导出字符串列表：**

   ```bash
   siglus-ssu -m /path/to/chapter1.dat
   # → 生成 /path/to/chapter1.dat.csv
   ```

2. **编辑 `chapter1.dat.csv`：** 在 `replacement` 列填入翻译文本。

3. **应用翻译：**

   ```bash
   siglus-ssu -m --apply /path/to/chapter1.dat
   ```

   `.dat` 文件被就地重写，保留原始的加密和 LZSS 状态。

#### `.dat.csv` 格式

| 列名 | 说明 |
|---|---|
| `index` | 编译后字符串表中的字符串索引（`str_id`）。 |
| `kind` | 字符串分类：`1 = dialogue`（台词）、`2 = speaker name`（说话人名）、`3 = other text`（其他文本）。 |
| `original` | 原始字符串值（转义编码）。 |
| `replacement` | 替换后的字符串值（转义编码）。初始与 `original` 相同。 |

`original` 与 `replacement` 中的特殊字符分别以 `\\`、`\n`、`\r`、`\t` 表示字面反斜杠、换行、回车和制表符。

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

> **注意：** `--a` 一定不需要 Pillow。提取 type3 JPEG payload 可以不依赖 Pillow；但 PNG 解码、合并模式、创建模式（包括需要读取 JPEG 尺寸的 type3 创建），以及 type0/type1/type2/type3 的更新路径都需要 [Pillow](https://pillow.readthedocs.io/)（`pip install pillow`）。

#### 语法

```
# 分析 .g00 文件（无需 Pillow）
siglus-ssu -g --a <input_g00>

# 将 .g00 提取为 PNG/JPEG
siglus-ssu -g --x [--trim] <input_g00 | input_dir> <output_dir>

# 将多个 .g00 文件（或 cut）合并为单张 PNG
siglus-ssu -g --m [--trim] <input_g00[:cutNNN]> <input_g00[:cutNNN]> [...] [--o <output_dir>]

# 从图片创建新的 .g00，或基于显式参考 .g00 执行更新
siglus-ssu -g --c [--type N] [--refer <ref_g00 | ref_dir>] <input_png | input_jpeg | input_json | input_dir> [output_g00 | output_dir]
```

#### 参数

| 参数 | 说明 |
|---|---|
| `--a` | **分析**模式。打印类型、画布尺寸、LZSS 统计；对于 type2，还会输出最多前 50 个 cut 的详细信息。 |
| `--x` | **提取**模式。解码每个 `.g00` 并写入 PNG 或 JPEG 文件；对于 type2，未使用 `--trim` 时还会额外写出一份可回灌的 `.type2.json` sidecar。若目标图片或 JSON 已存在，则跳过而不覆盖。 |
| `--trim` | 与 `--x` 使用时，写出前裁剪导出的图片。PNG 输出会优先裁到非透明像素区域，若整张图均不透明则改用左上角背景色；JPEG 输出使用左上角背景色，且无需裁剪时保留原始 payload。启用裁剪时不会写出 type2 JSON sidecar。与 `--m` 使用时，会裁掉合并后 PNG 四周的透明或纯背景色边缘。 |
| `--m` | **合并**模式。将多个 `.g00` 图片或 cut 合成为一张 PNG，保留 straight-alpha RGB，并按照所选 cut 的中心对齐 type2 图层。带 `--trim` 时，会裁掉合并后 PNG 四周的透明或纯背景色边缘。 |
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

# 合并并裁掉输出 PNG 边缘
siglus-ssu -g --m --trim /path/to/char_base.g00 /path/to/char_eye.g00 --o /path/to/merged_out/

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

目录输入的 `-g --x` 只扫描当前目录层级的 `.g00` 文件。
使用 `--trim` 时不会写出 type2 `.type2.json` sidecar，因为裁剪后的图片不再是可直接重建的布局。

#### 创建模式说明

- 省略 `--refer` 时进入创建模式。
- 当前已实现 **type0**、**type2** 与 **type3** 的创建。
- 默认推断规则：`png` -> type0，`jpg/jpeg` -> type3。创建 type2 时请显式指定 `--type 2` 并直接输入 `.type2.json`。
- 对于 `-g --x` 提取出的多 cut type2，回灌时应把自动导出的 `.type2.json` 直接传给 `-g --c`，而不是单张 `*_cutNNN.png`。
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
- `source_rect` 为可选；省略时使用整张源图；若此时也给出 `canvas_rect`，其宽高必须与整张源图一致。若同时给出 `source_rect` 与 `canvas_rect`，两者宽高必须一致。
- `center` 为可选，默认继承 `default_center` 或 `(0,0)`。
- 若追求稳定可复现的回灌，建议保留提取时生成的 JSON，只改动明确需要修改的 PNG 像素或矩形/中心点字段。

#### type2 提取与回灌资产

未使用 `--trim` 时，使用 `-g --x` 提取 type2 `.g00` 会在图片旁边写出 JSON sidecar；若目标已存在则跳过：
- Single-cut（单 cut）：`<basename>.png` + `<basename>.type2.json`
- Multi-cut（多 cut）：`<basename>_cut000.png`、`<basename>_cut001.png` ... + `<basename>.type2.json`

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
siglus-ssu -s --x <input_dir | input_file> <output_dir> [--trim <path_to_Gameexe.dat | Gameexe.ini>] [--angou <path|angou=text|key=bytes>]

# 分析音频文件，或比较两个 .ovk 文件
siglus-ssu -s --a <input_file.(nwa | ovk | owp)> [input_file_2.ovk]

# 创建/重新编码音频文件
siglus-ssu -s --c <input_ogg | input_dir> <output_dir>

# 使用 Gameexe 循环点播放单个循环 BGM 或目录播放列表
siglus-ssu -s --play <input_file.(nwa | owp | ogg) | input_dir> [path_to_Gameexe.dat | Gameexe.ini] [--angou <path|angou=text|key=bytes>]
```

#### 参数

| 参数 | 说明 |
|---|---|
| `--x` | **提取**模式。解码 `.owp` → `.ogg`，`.nwa` → `.wav`，`.ovk` → 单独的 `.ogg` 文件。 |
| `--a` | **分析**模式。打印单个音频文件的详细结构头部信息。提供两个 `.ovk` 文件时，会按条目编号/出现序号比较 size、sample count 和解密后的 Ogg payload 内容；对于 `z####.ovk` 文件名，还会报告推导出的全局 KOE 标签。 |
| `--c` | **创建**模式。将 `.ogg` 文件编码为 `.owp`，或将编号的 `.ogg` 文件组合编码为 `.ovk` 文件。目录输入时会递归扫描 `.ogg`，并在输出端保留相对目录结构。 |
| `--play` | **播放**模式。读取 `Gameexe.dat` 或 `Gameexe.ini` 中的 `#BGM.*` 循环点表，播放单个 `.nwa` / `.owp` / `.ogg` BGM，或播放一个可交互的目录播放列表。Gameexe 路径为可选；省略时会自动探测附近的 `Gameexe.dat`/`Gameexe.ini`。播放界面为整屏终端 UI，带实时进度条和播放列表视图。需要 `ffplay` 在系统 `PATH` 中，且已安装 [psutil](https://pypi.org/project/psutil/)。 |
| `--trim <Gameexe.dat \| Gameexe.ini>` | （仅提取模式）从 `Gameexe.dat` 或 `Gameexe.ini` 读取 `#BGM.*` 循环点表，并将 `.owp` 与 `.nwa` BGM 裁剪到其循环区域。`.owp` 裁剪会使用 **ffmpeg** 并输出 `.ogg`；`.nwa` 裁剪会直接截取解码后的 PCM 并输出 `.wav`。`.ovk` 文件不参与裁剪。 |
| `--angou <path\|angou=text\|key=bytes>` | 读取 Gameexe 来源时使用的加密 `Gameexe.dat` key 来源，例如 `--x --trim` 或 `--play`。使用 [`-a` / `--analyze`](#-a----analyze--分析和比较文件) 中说明的公共 key-source 规则。不读取 Gameexe 来源的 sound 操作也接受该参数，但会忽略它。 |

#### 示例

```bash
# 解码目录中的所有音频
siglus-ssu -s --x /path/to/bgm/ /path/to/ogg_out/

# 解码单个 .ovk 语音文件
siglus-ssu -s --x /path/to/z0001.ovk /path/to/ogg_out/

# 解码 .owp BGM 并按 Gameexe.dat 循环点裁剪
siglus-ssu -s --x /path/to/bgm/ /path/to/ogg_out/ --trim /path/to/Gameexe.dat

# 使用显式 Gameexe.dat key 来源解码并裁剪
siglus-ssu -s --x /path/to/bgm/ /path/to/ogg_out/ --trim /path/to/Gameexe.dat --angou /path/to/game_dir/

# 解码 .nwa BGM 并按 Gameexe.dat 循环点裁剪
siglus-ssu -s --x /path/to/nwa_bgm/ /path/to/wav_out/ --trim /path/to/Gameexe.dat

# 分析 .nwa 文件头
siglus-ssu -s --a /path/to/bgm01.nwa

# 分析 .ovk 归档表
siglus-ssu -s --a /path/to/z0001.ovk

# 比较两个 .ovk 文件
siglus-ssu -s --a /path/to/old/koe/z0001.ovk /path/to/new/koe/z0001.ovk

# 分析 .owp 文件
siglus-ssu -s --a /path/to/bgm01.owp

# 从起始点开始播放单个 .owp BGM，并按 Gameexe.dat 无限循环
siglus-ssu -s --play /path/to/bgm01.owp /path/to/Gameexe.dat

# 直接使用 Gameexe.ini 播放单个 .ogg BGM
siglus-ssu -s --play /path/to/bgm01.ogg /path/to/Gameexe.ini

# 播放目录中所有可匹配的 BGM；自动探测 Gameexe.dat/Gameexe.ini
siglus-ssu -s --play /path/to/BGM/

# 将 .ogg 文件重新编码为 .owp
siglus-ssu -s --c /path/to/translated_ogg/ /path/to/owp_out/
```

#### OVK 提取命名规则

提取包含多个条目的 `.ovk` 时，输出文件命名为：
- `<basename>.ogg` — 若只有一个条目。
- `<basename>_<entry_no>.ogg` — 若有多个条目（例如 `z0001_0.ogg`、`z0001_1.ogg`）。

#### OVK 创建命名规则

从目录创建 `.ovk` 时，命名为 `<basename>_<N>.ogg`（`N` 为整数）的文件只有在同组至少存在两份时，才会被分组打包为单个 `<basename>.ovk`。若某组只有一份带数字后缀的文件，当前实现会把它按普通单文件输入处理并输出 `.owp`。不带数字后缀的文件也会单独编码为 `.owp`。

#### 音频裁剪细节

`--trim` 会读取 Gameexe.dat/Gameexe.ini 中的 BGM 表（条目格式为 `#BGM.N = "...", "filename", start, end, repeat`），并将匹配到的 `.owp` 与 `.nwa` 文件裁剪到 `repeat` 与 `end` 之间的采样区间。对于 `.owp`，它会先解码为 `.ogg`，再调用 **ffmpeg** 写出裁剪后的 `.ogg`。对于 `.nwa`，它会解码为 PCM，直接截取采样区间，并写出裁剪后的 `.wav`，不需要 ffmpeg。`.ovk` 文件不参与裁剪。这对提取可无缝循环的背景音乐很有帮助。

#### 循环播放细节

`--play` 会从 `Gameexe.dat` 或 `Gameexe.ini` 读取 BGM 表，并按输入文件的 basename 匹配条目。Gameexe 路径是可选的；省略时，工具会先在音频目录的父目录中查找 `Gameexe.dat`，找不到时再回退到同一位置的第一个 `Gameexe.*` 文件（优先 `Gameexe.ini`）。

如果同一个物理文件在 `#BGM.*` 表中出现了多次，播放器会保留该文件对应的全部候选条目，而不是简单让后面的记录覆盖前面的记录。它会优先选择 `#BGM` 名称与当前文件 basename 完全一致的那一条，找不到时才回退到该文件的第一条记录。

它支持 `.nwa`、`.owp` 和普通 `.ogg` 输入。`.nwa` 会先解码成临时 `.wav` 再交给播放器。播放时会根据 Gameexe 采样点构造 **ffplay** filter：当 `start < repeat` 时，先播放一次 `start` → `repeat`，再循环 `repeat` → `end`；当 `start == repeat` 时，直接循环 `repeat` → `end`；当 `start > repeat` 时，先播放一次 `start` → `end`，再回到 `repeat` → `end` 循环。若 `end = -1`，或 `end` 超过了解码后音频的实际长度，则会自动将文件结尾视为循环终点。

当输入是目录时，播放器会递归扫描其中的 `.nwa`/`.owp`/`.ogg` 文件，并筛出能匹配 `#BGM.*` 条目的文件组成播放列表；不匹配的文件会输出跳过提示。随后会进入整屏终端 UI：顶部显示当前文件的完整路径，状态栏会显示当前处于首轮播放、循环段还是暂停状态，底部命令行仍可直接输入命令。

播放器支持 `p`（暂停/继续）、`q`（停止）、`h`（帮助），以及播放列表模式下的 `b`（上一首）、`n`（下一首）、`l`（将列表重新定位到当前曲目附近）、`play N`（跳转到从 1 开始的曲目编号）、`u` / `d`（列表上/下翻一页）、`gg` / `G`（跳到列表顶部/底部）。该模式用于预览 BGM 循环，不支持 `.ovk`。

目录输入的 `-s --x` 也会递归扫描子目录，并在输出端保留相对目录结构。

---

### `-v` / `--video` — 处理 `.omv` 视频文件

提供分析、提取和重新编译 `.omv` 视频文件的工具。`.omv` 格式是带有专有 SiglusEngine 包装头的 Ogg 容器（`.ogv`）。

`-v --c` 只保留输入 Ogg 文件中的第一条 Theora 视频流。若输入还包含 Vorbis、Opus、字幕或其他 stream，这些 stream 会被忽略，不会写入生成的 `.omv`。

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

#### 准备 `.ogv` 输入

提供给 `-v --c` 的 `.ogv` 应是只含视频的 Theora stream。若目标引擎要求 `yuv444p`，请显式设置 pixel format；FFmpeg 默认设置可能选择其他格式，例如 `yuv420p`。

请使用包含 `libtheora` 的 FFmpeg build。

```bash
ffmpeg -i input_video -map 0:v:0 -an -vf "format=yuv444p" -c:v libtheora -q:v 8 output.ogv
```

`-q:v 8` 只是示例质量设置，可按需要调整。

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

Patch 模式用于修改 `SiglusEngine.exe` 内部少量二进制值。

#### 语法

```bash
siglus-ssu -p --altkey <input_exe> <input_key> [-o output_exe] [--inplace]
siglus-ssu -p --lang (cjk | cjk-path | config.json) <input_exe> [-o output_exe] [--inplace] [--allow-partial] [--revert]
siglus-ssu -p --info <input_exe>
siglus-ssu -p --loc (0 | 1) <input_exe> [-o output_exe] [--inplace]
```

#### 参数

| 参数 | 说明 |
|---|---|
| `<input_exe>` | 要修改的 `SiglusEngine.exe` 路径。不接受符号链接；请直接传入真实 exe 路径。 |
| `<input_key>` | **仅 `--altkey` 使用**。新的 16 字节 key 来源，可指向 `key.txt`、`暗号.dat`、`SiglusEngine*.exe` 或 `Scene.pck` 文件路径，也可写成 `key=bytes` 字面量或 `angou=text` 字面量。不接受目录。这个位置参数只在 `--altkey` 模式有效。 |
| `-o`, `--output` | 输出 exe 路径。默认输出名为 `<stem>_alt.exe`、`<stem>_CJK.exe`、`<stem>_CJKPATH.exe`、`<stem>_LOC0.exe` 或 `<stem>_LOC1.exe`。若现有输出路径是符号链接则拒绝写入。 |
| `--inplace` | 直接覆盖输入 exe。不能与 `-o` / `--output` 同用。 |
| `--allow-partial` | 仅用于 `--lang`。即使当前引擎版本缺少预设中的部分组成项，也写出能够完成的修改。默认要求全部预设组成项满足。 |
| `--lang cjk` | 修改字体 charset、locale 与 `system.get_language`，用于 CJK 显示；不修改 `Gameexe.dat`、`Scene.pck`、`savedata` 路径。 |
| `--lang cjk-path` | 在 `cjk` 的基础上，把活动路径引用改向 `GameexeZH.dat`、`SceneZH.pck` 与 `savedata_zh`。 |
| `--lang config.json` | 从 JSON 应用完整的六字段语言配置。 |
| `--revert` | 使用语言补丁内嵌的配置和撤回数据，逐字节恢复原始 EXE。 |
| `--info` | 只打印可修改的 `ALTKEY`、`LANG`、`LOC` 信息，不写文件。 |
| `--loc 0` | 将匹配到的顶层地域检测例程改成恒通过 stub。 |
| `--loc 1` | 仅对本工具曾经用函数 stub 关闭地域检测的 exe 恢复原检测。 |

#### 语言预设

`--lang cjk` 会把日文/CJK charset 比较槽改为 `0x86`，并把活动 locale 字符串重定位到 `chinese`，把活动语言代码字符串重定位到 `zh`。

`--lang cjk-path` 会执行同样修改，把官方 ZH 路径字符串写入专用只读 PE 节，并把活动引用改向这些新字符串。规范化配置和精确撤回数据保存在不映射的文件尾 overlay 中。

JSON 配置只能包含 `pck`、`gameexe`、`save`、`charset`、`locale`、`language_code`，六个字段均为必填。已经应用语言补丁的 EXE 可以直接转换到另一份配置；工具会先在内存中恢复原始映像，再应用目标配置。

```json
{
  "pck": "SceneZH.pck",
  "gameexe": "GameexeZH.dat",
  "save": "savedata_zh",
  "charset": 134,
  "locale": "chinese",
  "language_code": "zh"
}
```

语言预设默认按完整事务执行：每个必需的 charset、locale、语言代码和所选路径都必须可修改或已经是目标值。不支持的引擎版本会报告缺少的组成项且不写输出。成功结果会先写入临时文件再原子替换；只有明确需要保留可用子集时才使用 `--allow-partial`。

#### Charset 槽位

`--info` 会显示经过验证的 `ENUMLOGFONT` charset 筛选循环。识别支持不同基址寄存器，并同时要求 `lfCharSet` 偏移、`0x11C` 记录步长和循环回边，因此不会把无关的零值结构标志当作 charset 槽。常见值如下：

- `0x00`（`ANSI_CHARSET`）：ANSI 字体搜索。
- `0x80`（`SHIFTJIS_CHARSET`）：Shift-JIS 字体搜索。
- `0x86`（`GB2312_CHARSET`）：GB2312 字体搜索。

CJK 预设只修改已识别的日文/CJK 槽；若没有找到此类槽，严格模式会把 charset 组成项报告为缺失，而不会猜测其他槽。

#### 示例

```bash
siglus-ssu -p --altkey /path/to/SiglusEngine.exe /path/to/key.txt -o /path/to/SiglusEngine_patched.exe
siglus-ssu -p --lang cjk /path/to/SiglusEngine.exe
siglus-ssu -p --lang cjk-path /path/to/SiglusEngine.exe --inplace
siglus-ssu -p --lang config.json /path/to/SiglusEngine.exe
siglus-ssu -p --lang config.json --revert /path/to/SiglusEngine_JSON.exe
siglus-ssu -p --info /path/to/SiglusEngine.exe
siglus-ssu -p --loc 0 /path/to/SiglusEngine.exe
siglus-ssu -p --loc 1 /path/to/SiglusEngine.exe --inplace
```

#### 输出

```
Input : /path/to/SiglusEngine.exe
Mode  : lang:cjk-path
SHA256(before): abc123...
SHA256(after) : def456...
Applied changes: N bytes
 - LANG charset: jp/shift-jis -> chs/gbk (1 bytes)
 - LANG string SceneZH.pck (N bytes)
 - LANG Scene: Scene.pck -> SceneZH.pck (N bytes)
Written: /path/to/SiglusEngine_CJKPATH.exe
```

`--info` 会打印带有代码引用的活动语言与路径槽：

```
Input : /path/to/SiglusEngine.exe
SHA256: abc123...
ALTKEY: 0xAA, 0xBB, ...
LANG charset1: 0x201BC8=0x00 (eng/ansi)
LANG charset2: 0x2BE1D3=0x80 (jp/shift-jis)
LANG presets: cjk, cjk-path
LANG Locale : japanese @ 0x677C94 refs=1
LANG Code   : ja @ 0x64FC6C refs=3
LANG Scene  : Scene.pck @ 0x66D208 refs=2
LANG Save   : savedata @ 0x66D814 refs=1
LANG Gameexe: Gameexe.dat @ 0x672C4C refs=1
LOC   : enabled (original function, func=0x22BF20)
```

---

### `-t` / `--tutorial` — 生成静态剧情图

从 `Scene.pck` 内的已编译场景数据生成静态剧情图 JSON。这个输出的目标是便于整体阅览，而不是试图模拟完整虚拟机执行。它会保留狭义台词，优先保证信息正确，不会为了“连得更全”而冒险猜测动态运行时才能确定的边。

命令还会在 JSON 旁边写出一个独立的 `tutorial_viewer.html`，随后尝试用系统默认浏览器打开。自动打开只是尽力而为，失败不会影响 JSON 生成。

#### 语法

```bash
siglus-ssu -t <input_pck> [output_json]
```

#### 参数

| 参数 | 说明 |
|---|---|
| `<input_pck>` | 要分析的 `Scene.pck`。 |
| `[output_json]` | 可选的输出 JSON 路径。不提供时，默认写到输入 `.pck` 同目录，文件名为 `<input_name>.tutorial.json`。 |

#### 输出内容

该命令会生成：

- 一个剧情图 JSON
- 同目录下的 `tutorial_viewer.html`

JSON 内包含图级元数据、节点 payload 台词，以及边的静态关系信息。viewer 可以直接打开该 JSON，也能在 `-t` 自动打开时通过 URL 参数自动加载，并按连通图逐个查看。

#### 这个图表示什么

- 节点 payload 使用狭义台词定义，也就是与 `-m` 提取结果中的 1 类字符串相对应的内容。
- 说话人归属采用保守策略。若源码没有足够静态依据可靠识别说话人，就只保留文本本身，不强行补名字。
- 整张图允许存在多个互不连通的分量。

#### 静态边策略

本模式明确以正确性优先：

- 会纳入：无需运行虚拟机、仅靠反汇编即可确认的直接静态控制流边，以及能静态解析目标的场景跳转边。
- 不会纳入：动态拼接目标、运行时分派、以及会把 helper / scheduler 场景误提升成剧情直边的模糊情况。

因此它是一个保守的下近似：可能缺少一部分真实但只能动态恢复的后续边，但应尽量避免输出误导性的假边。

#### Viewer 特性

生成的 viewer 支持：

- 拖拽加载 JSON
- 多个不连通图之间切换
- 力导布局与沿边移动的方向粒子
- 节点详情、场景名与自然行号显示
- 按台词 / 选项、节点编号、场景名、`scene @ line`（场景 @ 行号）搜索
- 英语 / 简体中文界面切换，以及亮色 / 夜间主题切换

#### 示例

```bash
# 在 Scene.pck 同目录生成 Scene.tutorial.json，并尝试自动打开 viewer
siglus-ssu -t /path/to/Scene.pck

# 输出到自定义 JSON 路径
siglus-ssu -t /path/to/Scene.pck /path/to/out/tutorial.json
```

### `test` — 回编测试

测试一个 `.pck`，或某个目录正下方的所有 `.pck`，能否在提取后原地回编。回编后的 `.pck` 字节完全一致时为 `EXACT`；`.pck` 不完全一致但规范化场景 payload 语义一致时为 `PAYLOAD_SAME`。

本模式面向带有内嵌原始源码数据的 `.pck`。如果某个 `.pck` 没有 OS 区段，就会跳过，因为没有可用于回编的原始 `.ss` 源码。

#### 语法

```bash
siglus-ssu test [--serial] <input_pck|input_dir>
```

`--serial` 会在回编阶段禁用并行编译；默认使用并行编译。

#### 流程

对每个 `.pck`，命令会：

1. 分析文件头，检查 `original_source_header_size` 是否表示存在 OS 区段；
2. 将 archive 解压到临时测试目录；
3. 对解压出的源码进行原地回编，并依次尝试 `const-profile` 0、1、2，直到某个 profile 得到 `EXACT` 或 `PAYLOAD_SAME`；
4. 先检查回编 `.pck` 是否与原始 `.pck` 字节完全一致；若不一致，再采用规范化的 `-a --payload` 语义比较；
5. 删除所有测试产生的临时文件。

#### 输出

分步骤日志只显示状态。原始与回编 `.pck` 字节完全一致时为 `EXACT`；字节不一致但规范化 payload 比较成功时为 `PAYLOAD_SAME`。不再使用 `PASS` 分类。`total` 行和最终汇总会记录已执行步骤的耗时，包括 `analyze`、`extract`、`compile`、`payload` 和 `cleanup`。如果编译经历 profile 回退，`compile` 耗时会包括所有尝试过的 profile。

只要还有 fallback profile 未尝试，编译错误会先静默捕获，不立即打印。只有所有 profile 都失败时，命令才会打印这些失败尝试的编译输出，并将该文件标记为 `FAIL`。

最终汇总会输出总计数，并且只列出失败文件的总耗时与步骤耗时。

当至少一个文件为 `EXACT` 或 `PAYLOAD_SAME`，且没有文件失败时，命令返回 `0`。只要有文件失败，或发现的文件全部被跳过，命令返回 `1`。

#### 示例

```bash
siglus-ssu test /path/to/Scene.pck
siglus-ssu test /path/to/pck_dir/
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
3. 对目录级全局 `.inc #command` 的实现唯一性与缺失实现，做出与当前 linker 相同的判定；
4. 对本节明确记载的实现怪癖，也应当保持一致，因为它们已经构成现行语言定义的一部分。

### 术语与翻译环境

#### 源文件集合

对单个 `.ss` 文件而言，其编译环境不是该文件自身，而是：

- 当前 `.ss` 文件；
- 与其位于同一目录的全部 `.inc` 文件；
- 由活动 `const.py` / `--const-profile` 提供的 form 与内建元素表。

同目录 `.inc` 文件按**文件名的小写排序**处理。

#### 解码与行结束符

`-c` 模式先按 `--charset` 指定或自动探测的编码严格解码每个源文件。解码会移除一个开头的 Unicode BOM，把 CRLF 和孤立 CR 行结束符归一化为 `\n`，但不执行 NFC、NFKC 或其他 Unicode 规范化；CA 阶段还会在字符级处理前删除任何残留的 `\r`。因此，SiglusSS 语言的后续规则只以这个归一化后的 LF 文本流为对象，与原始字节编码无关。

#### 规范术语

- **scene 文本**：`.ss` 文件中除 `#inc_start ... #inc_end` 区段以外、进入普通 scene 语法分析的部分；
- **scene 内嵌 inc 区段**：`.ss` 文件中由 `#inc_start` 与 `#inc_end` 包围、按 `.inc` 声明语法解释的部分；
- **全局 `.inc` 环境**：同目录全部 `.inc` 文件处理后得到的声明、替换和名字集；
- **良构程序**：在本规范全部前端与链接约束下被接受的源程序。

### 翻译阶段

对于一个 `.ss` 翻译单元，当前编译器的处理顺序可规范化为：

1. 读取并解码源文本；
2. 将 CRLF / 孤立 CR 行结束符归一化为 `\n`，并删除任何残留的 `\r`；
3. 对 scene 源文本做字符级处理：删除注释、在字符串与注释外折叠 ASCII 大写字母、处理 `#ifdef` / `#elseifdef` / `#else` / `#endif`，并抽取 `#inc_start ... #inc_end` 区段；
4. 先将抽取出的 scene 内嵌 inc 区段作为 `.inc` 文本，用 parent form = `scene` 处理；
5. 把上一步产生的声明和替换环境并入当前文件环境；
6. 对 scene 文本执行替换展开；
7. 对替换后的 scene 文本执行词法分析（LA）、语法分析（SA）、语义分析（MA）与字节码生成（BS）；
8. 当 `-c` 面向目录整体编译时，在所有 scene 前端阶段结束后，再执行目录级 linker 检查。

由此可知，下列事实都是规范性的：

- scene 级 `#ifdef` / `#elseifdef` / `#else` / `#endif` 发生在 scene 内嵌 inc 被分析**之前**；因此，scene 级条件编译看不到同一 `.ss` 文件稍后由 `#inc_start ... #inc_end` 声明出来的新名字；
- 目录级 `-c` compile 的语言定义，严格大于“单个 `.ss` 文件局部通过前端检查”。

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
3. 当前实现把它当作布尔状态而不是嵌套计数器处理，因此它**不支持嵌套的 `#inc_start` 区块**；
4. 缺失配对的 `#inc_end` 或未闭合的 `#inc_start` 都是不良构。

#### 源元数据注释

若源文件第一行以这个字节前缀开头：

```text
// #SCENE_SCRIPT_ID = dddd
```

其中 `dddd` 为四位十进制数字，则编译器会把这四位记录为场景元数据；第一行后续文本不会影响这次元数据读取。该注释不改变核心语法与静态语义，但属于当前实现接受的源格式组成部分。

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

单引号字面量与双引号字面量都不得跨物理行。唯一接受的转义写法是：

- `\\`
- `\n`
- 单引号字面量中的 `\'`，或双引号字面量中的 `\"`

在双引号字面量中，`\n` 会变成换行符。在单引号字面量中，当前 lexer 接受 `'\n'`，但产生的是字符 `n`，不是换行符；这个实现细节属于规范的一部分。单引号字面量必须按这条 lexer 规则**恰好产生一个字符**，否则不合法。字符字面量词法类型为 `VAL_INT`。双引号字面量词法类型为 `VAL_STR`。

#### 全角/双字节裸字符串

凡被 `is_zen()` 判定为 Windows CP932 双字节字符的连续序列（不含 `【` 与 `】`），都会直接词法化为 `VAL_STR`。这与官方编译器在日文 locale 下进行多字节转换的规则一致。因此，以下两种写法在词法上都能形成字符串 token：

```text
"こんにちは"
こんにちは
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
- `.inc #property` 与 `#command` 名字因此可以超出 scene 普通标识符字符集；
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
2. 实参与默认文本都按原始文本处理，并会先在当前替换环境下做文本展开，然后再代入；
3. 如果写了括号，参数列表就必须至少有一个参数；空的 `()` 不被接受。
4. 宏实参的分割遵循圆括号层级；字符串和字符字面量内部的逗号、括号不参与外层分割；
5. 宏体会带着一棵用于宏参数的临时替换树展开；最终结果插入后，扫描位置会推进到该插入结果末尾，因此不会在同一位置立刻重扫这段结果。

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

1. `property` 语句只能出现在 `command` 体内部；顶层 `property` 虽然能被语法识别，但语义上是不良构；
2. `if`、`for`、`while` 的条件应为 `int` 或 `intref`；
3. `switch` 条件应为 `int` / `intref` / `str` / `strref`；每个 `case` 值必须与条件同属整数家族或字符串家族；
4. `goto` 表达式 form 为 `void`；`gosub` 为 `int`；`gosubstr` 为 `str`；
5. `continue` 与 `break` 在循环外使用，将在 BS 阶段报错；
6. 某些 profile 标记为“选择分支相关”的命令，不得出现在条件、普通实参、goto 实参或下标表达式中；这是 profile 相关的额外静态限制；
7. `name-stmt` 产生名字显示事件；`text-stmt` 产生文本显示事件，并消耗一个 read flag 序号。

#### command 定义与声明匹配

scene 中的 `command` 定义有两种来源：

1. 它可能是纯 scene 局部命令；
2. 它可能是全局 `.inc #command` 声明的实现。

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

1. 全局 `.inc #command` 声明会进入目录级命令表；
2. 每个此类全局 `.inc #command` 都应由**恰好一个** scene 提供实现；
3. 若某命令被多个 scene 实现，linker 判为“defined more than once”；
4. 若某命令没有任何 scene 实现，linker 判为“is not defined”。

当前实现还有一个需要视为规范的怪癖：只有当 linker 在整个目录里至少见到过一个 scene `command` 标签之后，才会执行“缺失实现”检查。如果整个目录里完全没有任何 scene `command` 定义，当前 linker 不会报“is not defined”。

因此，一个实现若只复现单文件前端，而不复现该目录级约束，就不能视为与当前 `-c` 语言定义完全一致。

## 提示与故障排除

### 编译时的意外 token

如果本应作为一个参数的文本中含有逗号或括号等实参分隔符，请将它写成双引号字符串：

```
# 逗号会把这段文本拆成更多实参
mes(【主角】, 等一下，我需要考虑一下。)

# 加上双引号
mes(【主角】, "等一下，我需要考虑一下。")
```

### 字符串乘整数的异构乘法

官方编译器在普通二元 `*` 表达式上，会把右侧 form 按左操作数 (`exp_1`) 写入。本项目有意改为语义上更自然的右操作数 form (`exp_2`)。

有问题的语法，具体是指“作为取值使用的普通二元 `*` 表达式，并且其左操作数解引用后是字符串类、右操作数解引用后是整数类”。例如 `set_namae("ABC" * 3)`、`set_namae(s[0] * a[0])`、`s[0] = "ABC" * 3` 都属于这一类。

如果您需要一种在官方 `exp_1` 与本项目 `exp_2` 下都会编译出相同结果的源码写法，经验证可用的兼容写法是：先落到字符串引用上，再使用 `*=`。这个改写可以保持在同一行：

```ss
s[0] = "ABC" s[0] *= 3 set_namae(s[0])
```

不要改写成 `s[0] = s[0] * 3`，因为它仍然属于同一种有问题的普通二元 `*` 表达式。
