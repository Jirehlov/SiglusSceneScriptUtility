# SiglusSceneScriptUtility 使用手册

> **仅支持 CLI：** 本项目只支持 `siglus-ssu` 命令行接口，不支持直接导入或调用模块，也不对由此产生的任何问题负责。

**版本：** 0.5.9

**仓库：** [GitHub](https://github.com/Jirehlov/SiglusSceneScriptUtility)

**英文版：** [manual.md](manual.md)

---

## 目录

1. [概述](#概述)
2. [安装](#安装)
   - [方式一：从 PyPI 安装](#方式一从-pypi-安装)
   - [方式二：从源码安装](#方式二从源码安装)
3. [基本用法](#基本用法)
   - [全局选项](#全局选项)
   - [常量 profile](#常量-profile)
   - [场景字符串 XOR 乘数](#场景字符串-xor-乘数)
   - [命令别名](#命令别名)
   - [获取帮助](#获取帮助)
4. [模式参考](#模式参考)
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
   - [test — 回编测试](#test--回编测试)
5. [SiglusSS 语言规范](#siglusss-language-spec)

---

## 概述

使用 `siglus-ssu` 命令可编译和翻译 SiglusEngine 脚本，分析游戏数据，修改存档和引擎设置，处理媒体文件，并通过 LSP 为编辑器提供服务。处理场景脚本时，请选择对应作品的[常量 profile](#常量-profile)。

---

## 安装

### 方式一：从 PyPI 安装

需要 Python 3.12 或更高版本。

```bash
pip install siglus-ssu
```

平台专用 wheel 包含 Rust 加速。也可安装纯 Python wheel。

### 方式二：从源码安装

需要 Python 3.12+、[uv](https://github.com/astral-sh/uv) 和 [Rust 1.88+](https://rustup.rs/)。

在仓库根目录运行以下命令。

```bash
uv sync
uv run siglus-ssu --help
```

后续命令均使用 `uv run siglus-ssu`。

---

## 基本用法

```
siglus-ssu [-h] [-V|--version] [--legacy] [--legacy-full] [--const-profile N] [--string-xor-multiplier N] (-lsp|-c|-x|-a|-d|-k|-e|-m|-g|-s|-v|-p|test) [args]
```

程序会自动使用可用的原生加速。

在 Linux 和 macOS 上，程序会在不支持硬链接的文件系统上以复制方式写入禁止覆盖的输出。强制终止复制可能留下不完整的新文件。

就地应用翻译、修改存档或补丁 EXE 前，程序会检查原文件是否发生变化。操作中断后，输出目录中可能留有 `.siglus-update.lockdir`。请先确认没有更新正在运行，再删除这个目录。

### 全局选项

| 选项 | 说明 |
|---|---|
| `-h`, `--help` | 显示帮助。 |
| `-V`, `--version` | 显示已安装版本。 |
| `--legacy` | 使用 Python 编译，保留原生辅助加速。 |
| `--legacy-full` | 禁用全部 Rust 加速。 |
| `--const-profile N` | 选择对应作品的 profile（`0`–`10`，默认 `0`）。不能与 `-c --tmp` 同用。显式指定后，`test` 不再自动重试其他设置；`test --decompile` 必须指定。 |
| `--string-xor-multiplier N` | 覆盖场景字符串 XOR 乘数，接受 `0`–`0xFFFF` 的十进制或十六进制数值。Profile `3`、`5` 和 `8` 默认使用 `0`，其余默认使用 `0x7087`。详见[场景字符串 XOR 乘数](#场景字符串-xor-乘数)。 |

全局选项可放在模式前后，且须位于 `--` 之前。也可写作 `--const-profile=N` 和 `--string-xor-multiplier=N`。

### 常量 profile

各 profile 包含不同的内建类型、元素编号、命令签名和编译规则。下表列出各 profile 相对参考项的变化，并给出引擎或作品示例。

Profile `2` 为比较基准：场景字符串 XOR 乘数为 `0x7087`，局部 `property` 仅可声明于 `command` 内，`&&` 优先级高于 `||`，z-label 范围为 `#z0`–`#z999`。编译时会在 `global.ruby` 前插入消息块、为 `global.koe` 分配已读标记，并为 `global.sel`、`global.sel_cancel`、`global.selmsg`、`global.selmsg_cancel` 和 `global.sel_image` 生成选择块。

| Profile | 参考项 | 具体差异 | 引擎 / 作品示例 |
|---|---|---|---|
| `0` | `1` | 新增 `syscom.msg_back_get_chr_no`、`syscom.msg_back_get_koe_no`、`syscom.msg_back_get_message` 和 `syscom.msg_back_get_name`。 | 现代 SiglusEngine，默认选项。 |
| `1` | `2` | 新增 `joypad=1530`、`joystick=1540`、`joytrigger=1550` 和 `keyboard=1560` 类型，以及键盘/手柄输入、按钮查询和手柄模式设置接口。`keylist.clear`、`keylist.next`、`keylist.wait` 和 `keylist.wait_force` 在同一类型中分别改名为 `__clear`、`__next`、`__wait` 和 `__wait_force`。 | 官方引擎 `1.1.140.4`。 |
| `2` | — | 使用上方基准规则及 `keylist.clear`、`keylist.next`、`keylist.wait`、`keylist.wait_force`，不含 profile `1` 新增的类型和接口。 | 官方引擎 `1.1.137.0`。 |
| `3` | `2` | 场景字符串为明文（XOR 乘数 `0`），`global.koe` 不分配已读标记。 | TheGodofDeath HD。 |
| `4` | `2` | `global.wait_wipe`、`global.koe_wait_key`、`global.exkoe`、`pcmch.wait_key` 和 `pcmch.wait_fade_key` 的返回类型从 `int` 改为 `void`。编译时不生成选择块，也不应用选择命令的专用表达式限制。 | 原版 Rewrite。 |
| `5` | `3` | `global.wait_wipe`、`global.exkoe`、`global.exkoe_play_wait_key`、`counter.wait_key`、`pcmch.wait_fade_key` 和 `mov.play_wait_key` 的返回类型从 `int` 改为 `void`。编译时不在 `global.ruby` 前插入消息块。 | nanami/キサラギ。 |
| `6` | `2` | 允许在 `command` 外声明调用局部 `property`。 | カルマルカ。 |
| `7` | `4` | `counter.wait_key` 从 `int` 改为 `void`；允许在 `command` 外声明调用局部 `property`；`&&` 与 `\|\|` 同优先级、从左到右结合；z-label 限于 `#z0`–`#z99`。 | ルルミ和闇色。 |
| `8` | `5` | 类型编号为 `frameaction=1212`、`intlistref=11`；允许在 `command` 外声明调用局部 `property`；z-label 限于 `#z0`–`#z99`。`global.wipe(key_skip=...)` 和 `global.mask_wipe(key_skip=...)` 保留整数变量引用，其他整数表达式按值传递。 | Rewrite 体验版。 |
| `9` | `2` | 元素编号 `47` 对应 `worldlist` 类型的 `global.world` 属性，替代 `global.msgbtn` 命令。 | Rewrite Harvest festa! |
| `10` | `0` | 新增移动端 UI、触摸、网络、商店和扩展资源接口，包括 `global.sheet`、`global.touch`、`global.connect`、`global.appstore`、`global.googleplay` 和 `global.extend`。`global.message_box` 从返回 `void` 改为返回 `int`，并新增命名参数 `title_str`。 | FlixEngine（移动端 SiglusEngine）。 |

编译、反汇编、反编译和比较同一作品时，请使用同一个 profile。对于包含内嵌源码的 PCK，`siglus-ssu test Scene.pck` 会报告成功回编所用的 profile。

Profile `10` 的部分移动端接口使用内部占位名称 `mobile_*`。

### 场景字符串 XOR 乘数

作品的场景字符串编码与默认值不同时，可用 `--string-xor-multiplier N` 指定乘数。`0` 表示明文 UTF-16LE。场景字符串 XOR 独立于压缩和外层加密。`--no-angou` 保留场景字符串 XOR。

解码、修改和回编同一作品时，请使用相同的 profile 和乘数。一次命令对全部场景和比较输入使用同一乘数。提取目录不保存这些设置。乘数错误可能产生乱码。

修改乘数后，`-c --tmp` 的场景缓存会失效。普通提取、`--dat-repack` 和 `--gei` 忽略乘数。

明文场景字符串示例

```bash
siglus-ssu --string-xor-multiplier 0 -x --disam /path/to/Scene.pck
siglus-ssu --string-xor-multiplier 0 -m /path/to/extracted/chapter1.dat
siglus-ssu --string-xor-multiplier 0 -m --apply /path/to/extracted/chapter1.dat
siglus-ssu --string-xor-multiplier 0 -c /path/to/source/ /path/to/translated.pck
```

### 命令别名

`siglus-ssu help` 和 `siglus-ssu version` 分别等同于 `--help` 和 `--version`。

选择模式及必需的子操作后，可用 `--` 分隔以 `-` 开头的位置参数，例如 `siglus-ssu test -- --sample.pck`。所有选项必须放在 `--` 之前。对于以 `-` 开头的选项值，请使用绝对路径或加上 `./` 前缀。

长选项须完整输入。

### 获取帮助

```bash
siglus-ssu --help
```

各模式下的 `--help` 均显示同一份全局帮助。

---

## 模式参考

### `-lsp` — 启动语言服务器

```bash
siglus-ssu -lsp [--serial] [--read-sav /path/to/read.sav]
```

服务器通过标准输入输出为 `.ss` 和 `.inc` 提供诊断、语义高亮、补全、悬停、定义与引用查找、重命名和文档符号。全局 `--const-profile` 应与编译时一致。分析包括未保存的修改和同目录的 include 文件。

| 选项 | 说明 |
| --- | --- |
| `--serial` | 禁用场景并行扫描。 |
| `--read-sav PATH` | 在悬停说明中显示存档状态，并向 LSP 客户端提供读取和修改 flag 的请求。服务器可在存档可用前启动。 |

服务器按文档所在目录的场景和 include 文件检查命令链接。使用推送诊断时，服务器在编辑期间更新文件内诊断，并沿用缓存的链接结果。打开、保存或关闭带未保存修改的文件时，可触发链接复查。客户端主动请求诊断时，服务器使用当前源码，并在适用时检查链接。

设置 `SIGLUS_SSU_LSP_CACHE_DIR` 可更改工作区索引位置。服务器会重建不兼容的索引。

- Windows 优先使用 `%LOCALAPPDATA%\siglus_ssu\lsp-index`。首个环境变量为空或未设置时，改用 `%APPDATA%\siglus_ssu\lsp-index`。
- 各平台均可回退到 `$XDG_CACHE_HOME/siglus_ssu/lsp-index`。变量为空或未设置时，使用 `~/.cache/siglus_ssu/lsp-index`。

#### 已读 flag

flag 在每个场景内从 `0` 编号。存档中的零值表示引擎尚未将 flag 标记为已读。引擎可在显示内容之后再提交状态，例如等待或清屏时。服务器在场景名和 flag 数量匹配时将存档状态映射到当前源码。源码范围指向生成 flag 的文本、命令或宏调用。同一范围可对应多个 flag。

在 VS Code 扩展中打开 **SiglusSS: Read Flags**，启用模式并选择 `read.sav`。**Go to First/Last Unread Flag** 按当前场景的 flag 顺序跳转。**Go to Previous/Next Unread Flag** 按范围起点查找光标前方或后方的 flag，不循环。在编辑器右键菜单中选择 **Mark Flags as Read** 或 **Mark Flags as Unread**，可更新与选区重叠的全部 flag。没有选区且光标处有多个 flag 时，可从列表中选择一个。

`siglus/readFlags` 接收 `textDocument.uri`。传回上次的 `mappingId` 和 `saveRevision` 可复用源码范围。源码映射相同且存档变动时，`states` 返回 base64 编码的 flag 字节。映射和存档均无变化时，响应省略范围与状态字节。传入 `verifySave: true` 可重新核对存档内容。

客户端可从 `experimental.siglusReadFlags` 查询写入能力。`siglus/setReadFlag` 接收 `index`，`siglus/setReadFlags` 接收非空数组 `indices`。两种请求都须在 `textDocument` 中传入已打开文档的 URI 和版本，并传入当前 `mappingId` 和布尔值 `read`。服务器先校验映射与编号，再为批量编号去重，并在替换前核对原存档。成功响应包含更新后的计数、`previousRevision` 和 `saveRevision`。

---

### `-c` / `--compile` — 编译脚本

将场景 `.ss` 和同目录的 `.inc` 文件编译为 PCK。编译器只读取输入目录的当前层，包括以点开头的文件。

#### 语法

```
siglus-ssu -c [options] <input_dir> <output_pck | output_dir>
siglus-ssu -c --gei <input_dir | Gameexe.ini> <output_dir>
siglus-ssu -c --check <input_dir>
siglus-ssu -c --test-shuffle [seed0] [--csv <seed_csv>] <input_dir> <output_pck | output_dir> <test_dir>
```

#### 参数

| 参数 | 说明 |
|---|---|
| `<input_dir>` | 至少有一个带场景名的 `.ss`，可放入 `.inc`、`Gameexe.ini`、`暗号.dat` 和 `key.txt`。`--dat-repack` 和 `--gei` 的输入见下方。 |
| `<output_pck \| output_dir>` | 已存在的目录或以 `/`、`\` 结尾的路径会接收 `Scene.pck`，其他路径按精确的输出文件名处理。 |
| `--check` | 检查选中的场景和 include 源码，并校验目录中的 `Gameexe.ini`（如有）。编译器在内存中生成场景字节码，并检查每个已声明的全局命令是否恰好定义一次。只需传入 `<input_dir>`，不写入编译产物或缓存。不能与 `--tmp`、`--debug`、`--dat-repack`、`--gei`、`--test-shuffle` 或 `--csv` 同用。 |
| `--debug` | 编译后保留中间文件。不能与 `--tmp` 同用。 |
| `--charset ENC` | 为文本输入统一指定编码。默认逐文件检测 UTF-8 或 CP932，并根据 BOM 识别 UTF-16/32。Shift-JIS 别名使用 Windows CP932。可显式指定其他 Python 文本编码。 |
| `--allow-invalid` | 用指定编码或 BOM 对应的编码解码，并用 U+FFFD 替换无法解码的字节。自动检测时，若没有 UTF-16/32 BOM 且严格解码 UTF-8、CP932 均失败，则按 UTF-8 替换解码。 |
| `--no-os` | 不嵌入原始源码，不改变脚本的加密或压缩。 |
| `--dat-repack` | 打包现有场景 DAT。发现无效场景时停止写入。程序跳过非场景的 `Gameexe.dat` 和 `暗号.dat`，并从同目录 `.inc` 读取包级命令元数据。没有 include 时会警告。可用 `--no-os`、`--no-lzss`、`--charset`、`--allow-invalid` 和全局选项。有效的 `key.txt` 优先于 `暗号.dat`。 |
| `--no-angou` | 禁用 LZSS 压缩、外层 XOR 加密和原始源码嵌入，不关闭场景字符串 XOR。不能与 `--tmp` 同用。 |
| `--no-lzss` | 禁用 LZSS 压缩和原始源码嵌入，保留脚本加密。不能与 `--tmp` 同用。 |
| `--serial` | 依次编译场景脚本。打包可以使用多个工作线程。 |
| `--max-workers N` | 限制并行编译场景的工作数，须为正整数。默认每阶段用可用 CPU 数的一半，限制为 1–16。Windows 上的 Python 后端最多用 61 个工作进程。`--serial` 优先。 |
| `--set-shuffle SEED` | 设置字符串表乱序种子。接受 `0`–`0xFFFFFFFF` 的十进制或十六进制数值，默认 `1`，并启用 `--serial`。不能与 `--tmp` 同用。 |
| `--tmp <tmp_dir>` | 复用指定目录进行增量编译。串行构建从首个变化的场景开始重新编译，以保持字符串表顺序。并发构建需要各用一个缓存目录。不能与 `--debug`、`--dat-repack`、`--no-angou`、`--no-lzss`、`--set-shuffle`、`--test-shuffle`、`--csv`、`--gei` 或全局 `--const-profile` 同用。 |
| `--test-shuffle [seed0]` | 从 `seed0`（默认 `0`）搜索至 `0xFFFFFFFF`，找到任意一条与 `<test_dir>` 中全部参考 DAT 的字符串索引匹配的连续种子链。程序按固定的 Windows 文件名大小写映射查找同名 DAT，优先选用拼写完全一致的文件。可选种子后必须保留三个路径参数。省略种子时，可用 `--set-shuffle` 的值作为搜索起点。不能与 `--tmp` 或 `--gei` 同用。 |
| `--csv <seed_csv>` | 与 `--test-shuffle` 同用时，随链接后的 PCK 一并发布各场景的初始和最终种子。目录目标下的文件名为 `test_shuffle_seeds.csv`。 |
| `--gei` | 只将 `Gameexe.ini` 编译为 `Gameexe.dat`，输出按目录处理。输入目录没有 `Gameexe.ini` 时，命令会警告并跳过输出。不能与 `--tmp` 或 `--test-shuffle` 同用。 |

普通编译也不要求存在 `Gameexe.ini`，缺失时会跳过 `Gameexe.dat`。空 INI 会警告并继续编译。编译器会拒绝覆盖输入文件，并在本次产物全部生成后再写入输出目录。

构建中断后，可在缓存目录查找 `_compile.lockdir`，在各输出文件的实际父目录查找 `.siglus-publish.lockdir`。确认没有构建在使用相应目录后，再删除遗留的锁目录。

#### 示例

回编 `Output:` 后显示的提取目录：

```bash
siglus-ssu -c /path/to/translation_work/output_... /path/to/translated.pck
```

使用增量缓存，或限制并行工作数：

```bash
siglus-ssu -c --tmp /path/to/cache /path/to/src /path/to/Scene.pck
siglus-ssu -c --max-workers 2 /path/to/src /path/to/Scene.pck
```

打包已编译场景、单独编译 Gameexe，或搜索乱序种子：

```bash
siglus-ssu -c --dat-repack /path/to/dat_dir /path/to/repacked.pck
siglus-ssu -c --gei /path/to/src /path/to/out/
siglus-ssu -c --test-shuffle 12345 --csv /path/to/seeds.csv /path/to/src /path/to/out/ /path/to/original_dats/
```

#### 说明

- 源码处理与语法见[语言规范](#siglusss-language-spec)。
- **密钥兼容性：** 从 `暗号.dat` 或 `angou=text` 派生的密钥使用 CP932，可能与官方 Windows 转换结果不同。处理现有官方文件时，优先使用原始 16 字节密钥或对应引擎程序。普通编译时请将原始密钥写入 `key.txt`，并移走输入目录中优先级更高的 `暗号.dat`。
- 源码或对应的 DAT/LZSS 缓存变动或缺失时，编译器会重新编译该场景。Include 或编译设置变动可能使全部场景缓存失效。打包会复用未修改原始源码的压缩加密数据。
- 找不到匹配种子链时，程序不会写入 PCK 或 CSV。将报告中的首场景初始种子传给 `--set-shuffle` 可复现种子链。
- 多文件操作在各平台均按固定的 Windows 文件名大小写映射检查选中的输入。自动查找遇到名称冲突时会警告并选取一份。运行时场景名折叠 ASCII 大小写。内嵌源码保留文件名原拼写。

#### 编译统计

编译结束时会显示各阶段耗时及文件数。编译与场景压缩的计时区间可能重叠。`scene_files` 为场景总数，`compiled_scene_files` 为本次重建数。普通全量编译还会显示源码、已读标记和二进制大小统计。

---

### `-x` / `--extract` — 提取文件

普通提取写出已解码的场景 DAT 和内嵌源码。`--decompile` 写出 DAT，并从字节码重建源码。

#### 语法

```bash
siglus-ssu -x [--disam] [--decompile] <input_pck> [output_dir] [--angou <path|angou=text|key=bytes>]
siglus-ssu -x --disam <input_dir> [output_dir] [--angou <path|angou=text|key=bytes>]
siglus-ssu -x --gei <Gameexe.dat | input_dir> [output_dir] [--angou <path|angou=text|key=bytes>]
```

#### 参数

| 参数 | 说明 |
|---|---|
| `<input_pck>` | 要提取的场景 `.pck`。将加密场景解码成 DAT 需要有效密钥。 |
| `<input_dir>` | 与 `--disam` 同用时，扫描当前层的 `.dat`，跳过非场景文件。 |
| `[output_dir]` | 输出基目录，默认为输入文件所在目录或输入目录本身。PCK 提取会创建带时间戳的子目录。 |
| `--disam` | 额外写出 `<scene>.dat.txt` 反汇编，不能与 `--gei` 同用。 |
| `--decompile` | 从完整的场景 PCK 重建 `decompiled/<scene>.ss`，需要时生成 `decompiled/__decompiled.inc`。加上 `--disam` 可输出反汇编清单。 |
| `--angou VALUE` | 指定[解密密钥来源](#解密密钥)。 |
| `--gei` | 从 `Gameexe.dat` 或所在目录还原 `Gameexe.ini`。给定目录时，程序按固定的 Windows 文件名大小写映射查找，并对大小写冲突发出警告。已有同名文件时，依次尝试 `Gameexe_1.ini` 等文件名。 |

提取 PCK 时，程序在 `Output:` 后打印带时间戳的子目录，为重名输出添加数字后缀，并报告目标文件系统无法表示的文件名。可在该目录编辑内嵌源码，再将目录传给 `-c` 回编。

提取 PCK 时，如果密钥来源有问题，程序会发出告警并继续查找可用密钥。如果所有候选密钥都失败，程序会提取已有的内嵌源码，并将加密场景的原始字节保存为 `<scene>.enc`。反汇编和反编译需要解密后的 DAT。

如果场景和包内密钥文件都叫 `暗号.dat`，密钥会提取到 `.siglus-ssu-keys/`。编译和回包时可以从该目录读取密钥。

请使用作品对应的 profile 和字符串乘数。回编产物的字节布局可能不同。反汇编不完整时，反编译会失败。

FlixEngine 场景使用 profile `10`。Flix 资源 PCK 可用普通 `-x` 提取，也可用普通 `-a` 查看容器信息。

#### 示例

提取原始源码、反汇编 DAT 目录，或还原 Gameexe：

```bash
siglus-ssu -x /path/to/Scene.pck /path/to/translation_work/
siglus-ssu -x --disam /path/to/scene_dir/
siglus-ssu -x --gei /path/to/Gameexe.dat /path/to/output/
```

反编译并验证 profile `0` 的作品。请将 `output_...` 替换为提取时显示的目录，其他作品需使用对应的 profile 和乘数：

```bash
siglus-ssu --const-profile 0 -x --decompile /path/to/Scene.pck /path/to/translation_work/
siglus-ssu --const-profile 0 -c /path/to/translation_work/output_.../decompiled /path/to/rebuilt.pck
siglus-ssu --const-profile 0 -a --payload /path/to/Scene.pck /path/to/rebuilt.pck
```

按 [payload 比较结果](#payload-比较结果)检查是否一致。

---

### `-a` / `--analyze` — 分析和比较文件

支持分析 `.pck`、`.dat`、`.gan`、`.sav`、`.cgm` 和 `.tcr`。两个同类型文件会执行比较，不同类型文件会分别分析。分析失败时返回非零退出码。

#### 语法

```
siglus-ssu -a [--disam] <input_file> [input_file_2] [--angou VALUE]
siglus-ssu -a --payload <input_1.pck> <input_2.pck> [--angou VALUE]
siglus-ssu -a --payload [--disam] <input_1.dat> <input_2.dat> [--angou VALUE]
siglus-ssu -a [--readall|--apply] <input_file.sav>
siglus-ssu -a --read-flags <read.sav> [Scene.pck] [--report-json FILE] [--angou VALUE]
siglus-ssu -a --word <input_pck> [output_csv] [--angou VALUE]
siglus-ssu -a --angou VALUE
siglus-ssu -a --gei <Gameexe.dat> [Gameexe.dat_2] [--angou VALUE]
```

#### 参数

| 参数 | 说明 |
|---|---|
| `--disam` | 在各输入 `.dat` 旁写出 `<scene>.dat.txt` 反汇编，输入须为一个或两个场景 `.dat`。重建 `.ss` 请使用 `-x --decompile`。 |
| `--readall` | 将 `read.sav` 的全部场景标记为已读，或解锁 `global.sav` 中由引擎管理的 CG、BGM 和语音收集内容，不解锁 Steam 成就。重写存档前创建不覆盖旧文件的 `.bak` 备份。 |
| `--read-flags` | 将未读 flag 编号导出为 UTF-8 JSON，不修改存档。默认输出为 `<save_stem>.flags.json`。可选 PCK 用于校验场景名和数量、提供原始源码行号。`--angou` 仅在提供 PCK 时有效。 |
| `--report-json FILE` | 指定 `--read-flags` 报告路径，也接受 `--report-json=FILE`。缺失的父目录会自动创建，不允许覆盖输入存档、场景 PCK 或用于读取密钥的文件。 |
| `--apply` | 将同目录 `global.txt` 应用到 `global.sav`，写入前创建不覆盖旧文件的 `.bak`。可编辑项为 `G[n]`、`Z[n]`、`cg_table[n]`、`bgm_table[n]` 和 `chrkoe[n].look_flag`，其他字段会被忽略。 |
| `--word` | 按场景 `.dat` 和内嵌 `.ss` 统计台词单位，显示汇总并写入 CSV。默认输出为输入旁的 `<pck_stem>.word.csv`，目录目标使用该文件名。不允许覆盖输入 PCK 或用于读取密钥的文件。 |
| `--payload` | 对两个 `.pck` 或两个 `.dat` 执行规范化场景 payload 比较，详见 [payload 比较结果](#payload-比较结果)。 |
| `--angou VALUE` | 为 PCK/DAT/Gameexe 操作提供密钥，或单独查看密钥，详见[解密密钥](#解密密钥)。 |
| `--gei` | 分析或比较 `Gameexe.dat`，仅可与 `--angou` 同用。 |

`--readall`、`--apply`、`--read-flags` 和 `--word` 是独立操作，不能相互组合，也不能与比较选项同用。`--word` 可使用 `--angou`。`.gan`、`.cgm` 和 `.tcr` 的结构比较会在任一输入无法完整解析时失败。

内嵌 `.ss` 包含 `SCENE_SCRIPT_ID` 时，PCK 报告会显示 `ID` 列，并将 ID 纳入比较。

#### 解密密钥

将 `--angou VALUE` 放在参数末尾。使用 `--` 分隔符时，放在分隔符之前。`VALUE` 须为单独的非空参数。

| 值 | 含义 |
|---|---|
| 文件路径 | 从 `暗号.dat`、`key.txt`、`Scene.pck` 或 `SiglusEngine*.exe` 读取密钥。 |
| 目录路径 | 搜索该目录当前层文件。 |
| `angou=text` | 从字面量形式的 `暗号.dat` 首行派生密钥。 |
| `key=bytes` | 指定 16 字节密钥，建议使用明确的 `0xNN` 写法，避免数字歧义。 |

程序依次查找显式密钥来源、输入 PCK 的内嵌密钥、输入目录和父目录。若显式指定的文件或目录能提供密钥，程序会跳过父目录。目录内依次查找 `Scene.pck`、`Scene*.pck`、`暗号.dat`、`key.txt` 和 `SiglusEngine*.exe`，只查当前层。提取 PCK 或反汇编 DAT 目录时，`-x` 会告警并跳过无效的显式密钥来源和无法读取的密钥目录。其他命令要求显式来源能提供密钥。候选密钥无法解密时，程序可尝试后续候选项。

加密的 `Gameexe.dat` 要求去掉注释后的每个非空行都是配置赋值，例如 `#WINDOW_XSIZE=640`。可省略 `#`。名称以 ASCII 字母、数字或下划线开头，也可包含点、方括号、连字符、空格或制表符。值可含 Unicode。候选密钥解出不同的有效文本时，解密会失败。

`暗号.dat` 和 `angou=text` 的文本密钥可能与官方 Windows 转换结果不同。处理现有官方文件时，优先使用对应引擎或原始密钥。包内的 `暗号.dat` 支持带 BOM 的 UTF-16 或 UTF-32。恰好 16 字节的 `key.txt` 按二进制读取。其他文本密钥依次按 `0xNN`、两位十六进制、十进制解析，取首个适用格式的前 16 个数值。因此，16 个 `10` 表示十六进制 `0x10` 字节。

```bash
siglus-ssu -x /path/to/Scene.pck --angou /path/to/SiglusEngine.exe
siglus-ssu -a --angou "angou=literal_angou_string"
siglus-ssu -a --angou "key=0xA9,0x86,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00"
```

#### read flag JSON

零值 flag 表示未标记已读，不一定表示对应内容从未显示过。每个场景的 flag 从 `0` 编号。

报告包含 `savePath`、`pckPath`（未提供 PCK 时为 `null`）、`summary` 和 `scenes`。汇总包括场景数、flag 数、已读与未读数和各状态数量。每个场景包括名称、状态、存档与 PCK 的 flag 数、已读与未读数，以及 `unreadFlags`。每个未读项包含 `index` 和 `line`。匹配后的 `line` 是从 `1` 开始的原始源码行号，不适用于反编译源码。不可用值为 `null`。

| 场景 `status` | 含义 |
|---|---|
| `notChecked` | 未提供 PCK，未校验存档编号。 |
| `matched` | 场景名和 flag 数量一致。 |
| `ignored` | 存档场景不存在于 PCK，引擎会忽略。 |
| `countMismatch` | flag 数量不同，引擎会忽略这些存档标记。 |
| `sceneUnavailable` | 无法解码 PCK 场景或 flag 表。 |

报告只列出存档记录，不含存档记录的 PCK 场景在游戏中初始为未读。报告保留全部存档计数与编号，包括被忽略或不匹配的记录。`countMismatch` 或 `sceneUnavailable` 会在报告写出后返回 `1`，`ignored` 不会导致失败。

#### payload 比较结果

比较范围包括字节码、标签、属性、字符串（包括未使用的字符串）、已读标记及包级命令和属性路由，不包括字符串存储顺序、Z 标签表末尾未使用的零项和仅供调试的名称数据。标识符名称参与比较。

| `.pck` 场景的 `PAYLOAD` | `.dat` 结果 | 含义 |
|---|---|---|
| `same` | `identical` | 规范化 payload 一致。 |
| `text_only` | `text_only` | 结构相同，字符串不同；资源名或场景名也可能不同，进而影响行为。 |
| `real_diff` | `real_diff` | 其他 payload 数据不同。 |
| `-` | `unavailable` | 场景缺失或无法解码。 |
| `INCOMPLETE` | `INCOMPLETE` | 反汇编或校验不完整，即使输入字节相同也不能判定一致。 |

整个 PCK 的 payload 一致要求没有新增或缺失场景，也没有 `text_only`、`real_diff`、不可用或 `INCOMPLETE` 结果。文件头和内嵌源码差异单独报告。差异表不显示已验证相同的场景，payload 汇总只统计表中场景。

差异本身属于比较结果，仅凭退出状态 `0` 不能判定一致。`INCOMPLETE` 返回 `1`。

#### 示例

分析和比较文件：

```bash
siglus-ssu -a /path/to/Scene.pck
siglus-ssu -a --payload /path/to/original.pck /path/to/rebuilt.pck
siglus-ssu -a --disam /path/to/chapter1.dat
```

导出未读标记，或将全部场景标记为已读：

```bash
siglus-ssu -a --read-flags /path/to/savedata/read.sav /path/to/Scene.pck
siglus-ssu -a --readall /path/to/savedata/read.sav
```

分析 `global.sav` 生成 `global.txt`，编辑支持的值后再应用。分析时会保留已有的 `global.txt`。

```bash
siglus-ssu -a /path/to/savedata/global.sav
siglus-ssu -a --apply /path/to/savedata/global.sav
```

#### 台词计数输出（`-a --word`）

```bash
siglus-ssu -a --word /path/to/Scene.pck /path/to/counts.csv
```

计数单位并非统一的语言学词数，具体规则为：

- 汉字、平假名、片假名和注音符号按字符计数，半角片假名与随后浊点或半浊点合计一个单位。
- 韩文、其他字母和数字按连续词段计数。
- 词内撇号、连字符和下划线连接词段，十进制数字之间的 `.`, `,`, `/`, `:` 及全角形式连接数字段。
- 标点、空白、emoji 和其他符号不增加计数。

台词计数支持 `print` 输出由字符串字面量拼接或重复得到的文本。重复次数可以使用整数字面量、正负号和整数加减乘运算。

| CSV 列 | 含义 |
|---|---|
| `type` | `dat` 或 `ss`。 |
| `path` | PCK 内的相对路径。 |
| `status` | `ok`、`failed` 或 `unavailable`。 |
| `dialogue_lines` | 台词条目数。 |
| `dialogue_count` | 台词单位总数。 |
| `error` | 失败原因，无错误时为空。 |

失败或不可用行的计数为空，汇总仅计入成功行。部分失败时，命令会先写出结果，再返回 `1`。已声明的源码区段缺失或无法读取时，`ss_status=unavailable`、源码总数为 `N/A`。不含内嵌源码的 PCK 只生成 DAT 行，`ss_status=not_embedded`，且在全部 DAT 计数成功时返回成功。源码计数与编译一样在 DOS EOF 处停止。

---

### `-d` / `--db` — 导出和编译 `.dbs` 数据库

将游戏数据库导出为 CSV，并将编辑后的 CSV 编译回 `.dbs`。

#### 语法

```
siglus-ssu -d --x <input_dir | input_file.dbs> <output_dir>
siglus-ssu -d --a <input_file.dbs> [input_file_2.dbs]
siglus-ssu -d --c [--type N] [--set-shuffle SEED] <input_csv | input_dir> <output_dbs | output_dir>
siglus-ssu -d --c [--type N] [--set-shuffle SEED] --test-shuffle [skip0] <expected.dbs> <input_csv> <output_dbs | output_dir>
```

| 参数 | 说明 |
|---|---|
| `--x` | 将 `.dbs` 导出为 CSV，保留已有的 CSV。 |
| `--a` | 分析一个数据库或比较两个数据库。 |
| `--c` | 将 CSV 编译为 `.dbs`。 |
| `--type N` | 输出数据库类型（`0`–`2147483647`）。普通创建默认用 `1`。`--test-shuffle` 默认采用参考 DBS 的类型。类型 `0` 的字符串使用 CP932，其他类型使用 UTF-16LE。 |
| `--set-shuffle SEED` | 设置随机填充种子，支持十进制或十六进制，默认 `1`。 |
| `--test-shuffle [skip0]` | 从 `skip0`（默认 `0`）开始，尝试最多 16,777,216 个随机数跳过次数，以匹配参考数据库的填充。仅在逐字节一致时写出结果，保留参考文件。仅用于单文件模式。 |

目录导出与编译会递归扫描，并保留子目录结构。批量编译会拒绝 `name.csv`、`name.dbs.csv` 等输出重名项，包括仅大小写不同的重名。

比较按解码后的字符串值进行，最多检查 2,000,000 个单元格、显示 20 处差异，并在达到上限时提示。

#### 示例

```bash
siglus-ssu -d --x /path/to/dbs_dir/ /path/to/csv_out/
siglus-ssu -d --c /path/to/gamedb.dbs.csv /path/to/translated.dbs
siglus-ssu -d --a /path/to/original.dbs /path/to/translated.dbs
```

#### CSV 格式

CSV 使用带 BOM 的 UTF-8 及 CRLF，可用 Excel 编辑。请保留前两行及第一列：

- `#DATANO`：首格为 `#DATANO`，后续为各列调用号。
- `#DATATYPE`：对应列的类型，常见值为 `S`（字符串）和 `V`（数值/32 位数据）。
- 数据行：首格为行调用号，后续值按表头顺序排列。

行、列调用号必须在有符号 32 位整数范围内。

使用标准 CSV 引号规则：双引号写成两个双引号，反斜杠保留原样，换行和制表符直接写入带引号的字段。遇到引号格式错误、字段过多或无法编码的字符串时，编译会报错并显示 CSV 位置。

---

### `-k` / `--koe` — 按角色收集语音文件

将场景中的语音引用匹配到 `.ovk` 条目，按角色提取 `.ogg`，并生成包含台词和调用位置的 `koe_master.csv`。

#### 语法

```
siglus-ssu -k [--stats-only] <scene_input> <voice_dir> <output_dir> [--angou VALUE]
siglus-ssu -k [--stats-only] --single KOE_NO <voice_dir> <output_dir>
```

| 参数 | 说明 |
|---|---|
| `<scene_input>` | `Scene.pck`、单个场景 `.dat` 或递归扫描的 DAT 目录。`--single` 不使用此参数。 |
| `<voice_dir>` | 一个 `zNNNN.ovk` 归档，或包含此类归档的目录。目录只扫描当前层。`NNNN` 是四位场景编号。 |
| `<output_dir>` | 音频输出目录，普通模式下还会生成 `koe_master.csv`。 |
| `--angou VALUE` | 加密场景的[解密密钥来源](#解密密钥)，不能与 `--single` 同用。 |
| `--stats-only` | 仅写出 CSV 和摘要，不提取音频。与 `--single` 同用时仅显示摘要。 |
| `--single KOE_NO` | 提取一个全局语音编号，直接输出为 `KOE(XXXXXXXXX).ogg`，不生成 CSV 或角色子目录。编号不存在时返回 `1`。 |

#### 输出结构

```
<output_dir>/
  koe_master.csv
  <character name or %EMPTY>/KOE(000000001).ogg
  unreferenced/KOE(000000002).ogg
```

`%EMPTY` 表示未找到角色名。目录名中的非法字符会按百分号转义，CSV 中保留原始角色名。仅大小写不同的名称遵循输出文件系统的规则。

遇到场景扫描或 OVK 索引错误时，命令会在写出 CSV 或语音前退出。CSV 不能覆盖用于读取密钥的文件。未被引用的归档条目写入 `unreferenced/`。摘要中的语音总时长仅包括被引用条目。无法读取的时长计入 `Duration failed`，不妨碍 CSV 输出。

#### `koe_master.csv` 格式（仅普通模式）

| 列 | 说明 |
|---|---|
| `koe_no` | 全局语音编号，计算方式为 `scene_no × 100000 + entry_no`。 |
| `character` | 从场景推断的角色名。 |
| `text` | 对应台词。 |
| `duration_sec` | 时长，单位为秒，不可用时为空。 |
| `callsite` | 分号分隔的 `filename:line`，PCK 输入时为 `Scene.pck!scene.dat:line`。 |

同一语音编号对应不同角色或台词时，CSV 会保留独立行；同一组合的重复引用则合并为一行。可识别的条件分支备选角色名也会保留，每份音频仅使用一个推断出的目录名。

#### 示例

```bash
siglus-ssu -k /path/to/Scene.pck /path/to/voice/ /path/to/voice_out/
siglus-ssu -k --stats-only /path/to/scene_dir/ /path/to/voice/ /path/to/voice_out/
siglus-ssu -k --single 123456789 /path/to/voice/ /path/to/voice_out/
```

---

### `-e` / `--exec` / `--execute` — 从指定标签启动引擎

从场景的指定 `#z` 标签启动 `SiglusEngine.exe`。需要兼容的 Windows 运行环境，本命令不配置或调用 Wine。

```
siglus-ssu -e <path_to_engine> <scene_name> <label>
```

| 参数 | 说明 |
|---|---|
| `<path_to_engine>` | `SiglusEngine.exe` 路径。 |
| `<scene_name>` | 非空的纯场景名，可带 `.ss` 后缀，不接受目录部分或纯空白名称。 |
| `<label>` | 非负十进制标签编号。可带 `#`、`z` 或 `#z` 前缀。 |

命令会在程序旁创建或复用 `work_YYYYMMDD`，启动引擎后立即返回，并保留工作目录。

```bash
siglus-ssu -e /path/to/SiglusEngine.exe chapter2 5
siglus-ssu -e /path/to/SiglusEngine.exe chapter2.ss "#z5"
```

---

### `-m` / `--textmap` — 翻译用文本映射

将场景 `.dat` 字符串导出为 CSV，并就地应用译文，不支持修改 `.ss` 源码。

```
siglus-ssu -m <path_to_dat | path_to_dir> [--angou VALUE]
siglus-ssu -m --apply <path_to_dat | path_to_dir> [--angou VALUE]
```

程序会递归扫描指定目录，并跳过配置和密钥文件。处理加密文件时，程序先按指定目录查找[解密密钥](#解密密钥)。如果这些密钥无法解开子目录中的 DAT，程序会从该 DAT 所在的目录继续查找。

#### 操作流程

1. 在 DAT 旁导出 `chapter1.dat.csv`。重新导出会保留已有的 CSV。

   ```bash
   siglus-ssu -m /path/to/chapter1.dat
   ```

2. 编辑 CSV 的 `replacement` 列，保留 `index` 和 `original`。
3. 应用译文：

   ```bash
   siglus-ssu -m --apply /path/to/chapter1.dat
   ```

命令会重写 DAT，并保留原有加密和压缩状态。应用译文前请备份原文件。

CSV 必须包含 `index`、`original` 和 `replacement`。遇到无效或重复编号、原文不匹配时，命令会保留原 DAT 并返回 `1`。已应用的行可以重复提交。目录处理会在失败后继续，并在任一文件失败时返回 `1`。

#### `.dat.csv` 格式

| 列 | 说明 |
|---|---|
| `index` | 字符串表编号。 |
| `kind` | `1` = 台词，`2` = 角色名，`3` = 其他文本。 |
| `original` | 原始字符串，按下方规则转义。 |
| `replacement` | 替换字符串，初始与 `original` 相同。 |

反斜杠、换行、回车和制表符分别写为 `\\`、`\n`、`\r` 和 `\t`。孤立的 UTF-16 代理码元使用 `\uD800`–`\uDFFF` 转义。

---

### `-g` / `--g00` — 处理 `.g00` 图片文件

支持分析、提取、合并、创建和更新 SiglusEngine 图片。

| 类型 | 内容 |
|---|---|
| type0 | 不透明图片，解码为 32 位 BGRA。 |
| type1 | 调色板图片，最多 256 色。 |
| type2 | 多个图片 cut 及位置数据。 |
| type3 | JPEG 图片。 |

图像处理需要 [Pillow](https://pillow.readthedocs.io/)（`pip install pillow`）。分析和不裁剪的 type3 JPEG 提取无需 Pillow。不裁剪时，程序会校验 JPEG 主图的标记，并原样写出 JPEG 数据。

#### 语法

```
siglus-ssu -g --a <input_g00>
siglus-ssu -g --x [--trim] <input_g00 | input_dir> <output_dir>
siglus-ssu -g --m [--trim] <input_g00[:cutNNN]> <input_g00[:cutNNN]> [...] [--o <output_dir>]
siglus-ssu -g --c [--type N] [--refer <ref_g00 | ref_dir>] <input_png | input_jpeg | input_layout | input_dir> [output_g00 | output_dir]
```

| 参数 | 说明 |
|---|---|
| `--a` | 显示图片类型、尺寸及 cut 信息。 |
| `--x` | 提取 PNG/JPEG，未裁剪的 type2 还会生成可回编的 `.type2.json`。已存在的图片和 JSON 目标会被跳过。 |
| `--trim` | 裁去透明边缘，或不透明图片中与左上角同色的背景。仅用于 `--x` 和 `--m`，裁剪的 type2 不生成 JSON 布局。 |
| `--m` | 合并图片或 cut 为 PNG，按中心位置对齐 type2 cut。 |
| `--c` | 创建 G00，或根据 `--refer` 更新。 |
| `--o`、`-o`、`--output`、`--output-dir` | 合并输出目录，默认当前目录。 |
| `--type N`、`--t N` | 指定创建类型，或校验更新时的参考类型，仅用于 `--c`。 |
| `--refer <ref_g00 \| ref_dir>` | 按参考文件更新。目录输入须给参考目录。单文件输入可给参考文件或目录。查找参考文件时若有大小写冲突，程序会警告。省略输出路径时就地更新参考文件。 |
| `:cutNNN` | 合并时指定 type2 cut，例如 `sprite.g00:cut002`。 |

目录提取和创建仅扫描当前层。生成新的 type2 布局时，程序会校验已有 cut PNG 的可读性和未裁剪尺寸。校验失败时，程序会报错。

#### 创建与更新

创建时，PNG 默认生成 type0，JPEG 默认生成 type3。Type0 输出的 alpha 为 255。用 `--type 2` 从图片或 `.json`/`.jsonc` 布局创建 type2。单张图片优先采用 `sprite.type2.json` 等同名布局，找不到时生成单 cut。输入为目录时，`--type 2` 优先处理布局，找不到时处理图片。创建支持类型 0、2、3。

创建时省略输出路径，文件会写到输入旁。各输出路径须互不相同，不可覆盖源图、布局或其他输出的参考文件。就地更新会在替换前核对参考文件。中断后，请确认无更新运行再删除 `.siglus-g00.lockdir`。

JSON/JSONC 布局用于创建。参考文件包含多个 cut 时，用 `<basename>_cut###.png` 命名单个替换图。

```bash
siglus-ssu -g --x /path/to/sprite.g00 /path/to/work/
siglus-ssu -g --m /path/to/sprite.g00:cut005 /path/to/overlay.g00 --o /path/to/out/
siglus-ssu -g --c /path/to/new_bg.png /path/to/game_bg.g00
siglus-ssu -g --c /path/to/new_bg.png /path/to/game_bg.g00 --refer /path/to/original_bg.g00
```

#### type2 JSON 布局

未裁剪的 type2 提取会生成 `<basename>.type2.json`，以及单 cut 的 `<basename>.png` 或多 cut 的 `<basename>_cut000.png`、`<basename>_cut001.png` 等。编辑 PNG 后，从 JSON 回编：

```bash
siglus-ssu -g --c --type 2 /path/to/work/sprite.type2.json /path/to/rebuilt/sprite.g00
```

使用布局回编全部 cut。提取会保留透明像素下的 RGB。回编直接使用编辑后的 PNG 像素值。

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

- `canvas`：输出画布尺寸。
- `cuts` 按顺序分配编号。单个 cut 可显式设置 `index`。`null` 留空。
- `source` 可相对于布局文件填写。接受 `/` 和 `\`。cut 未指定 `source` 时，采用 `default_source` 或随命令传入的图片。
- `canvas_rect`：放置位置。可选 `source_rect` 用于截取 PNG，省略时使用整张图片。源矩形和画布矩形的尺寸必须一致。
- `center`：每个 cut 的中心，默认使用 `default_center`，均缺省时为 `(0, 0)`。

---

### `-s` / `--sound` — 处理音频文件

| 格式 | 提取结果 |
|---|---|
| `.nwa` | `.wav` |
| `.owp` | `.ogg` |
| `.ovk` | 按编号提取的 `.ogg` 语音 |

#### 语法

```
siglus-ssu -s --x <input_dir | input_file> <output_dir> [--trim <Gameexe.dat | Gameexe.ini>] [--angou VALUE]
siglus-ssu -s --a <input_file.(nwa | ovk | owp)> [input_file_2.ovk]
siglus-ssu -s --c <input_ogg | input_dir> <output_dir>
siglus-ssu -s --play <input_file.(nwa | owp | ogg) | input_dir> [Gameexe.dat | Gameexe.ini] [--angou VALUE]
```

| 参数 | 说明 |
|---|---|
| `--x` | 提取音频，目录输入会递归扫描并保留子目录。会覆盖已有输出，批次内的输出不得相互冲突，也不能覆盖本次操作读取的文件。 |
| `--a` | 分析一个音频文件，或比较两个 OVK 的条目。 |
| `--c` | 按下方命名规则从 Ogg 创建 OWP 或 OVK，目录输入会递归扫描并保留子目录。 |
| `--play` | 按 Gameexe 循环点在终端中预览 BGM，需要 `PATH` 中的 `ffplay` 和 `psutil`（`pip install psutil`）。支持 NWA/OWP/Ogg，不支持 OVK。 |
| `--trim <Gameexe.dat \| Gameexe.ini>` | 仅提取匹配 NWA/OWP 的 `repeat`–`end` 循环段。OWP 裁剪需要 `ffmpeg`，NWA 不需要。不裁剪 OVK。 |
| `--angou VALUE` | 用于裁剪或播放时解密 Gameexe 数据的[密钥来源](#解密密钥)，其他音频操作会忽略。 |

程序会在音频解码失败、所选循环段没有采样或 NWA 压缩块不完整时报错，并保留该曲目的已有输出。

#### OVK 命名

单条目提取为 `<basename>.ogg`，多条目提取为 `<basename>_<entry_no>.ogg`。创建或提取 OWP 和 OVK 时，Ogg 流必须完整。提取 OVK 时，程序会读完归档的全部条目再写出文件。发现索引变化时，程序会停止处理该归档并保留已有的输出文件。遇到写入失败时，程序会撤销本次对该归档输出文件的更改。

创建时，至少两个 `<basename>_<N>.ogg` 会合并为 `<basename>.ovk`。其他文件，包括只有一份的编号文件，均单独生成 OWP。创建 OVK 和循环播放时，串联 Ogg 音频的各段须使用相同采样率。循环播放还要求各段的编码和声道数一致，FLAC 还要求各段位深一致。对于 Vorbis、Opus、Speex 和 FLAC，程序从各段的实际音频起点计算采样数。

#### 循环播放

播放器按音频主文件名匹配 `#BGM.*` 条目。未指定 Gameexe 路径时，先在音频目录的父目录查找 `Gameexe.dat`，再查找附近的 `Gameexe.*`，回退文件中优先使用 INI。同一文件对应多个条目时，优先使用 BGM 名称匹配项，其次使用首个条目。

播放从 `start` 开始，并在 `repeat`–`end` 之间循环。`end=-1` 或超出音频长度时按文件末尾处理。目录输入会递归收集匹配曲目，并提示跳过未匹配文件。

| 命令 | 操作 |
|---|---|
| `p`、`q`、`h` | 暂停/继续、退出、帮助。 |
| `b`、`n` | 播放列表上一首/下一首。 |
| `play N` | 播放列表中第 `N` 首，从 `1` 开始。 |
| `l` | 将当前曲目移回列表视野中心。 |
| `u`、`d` | 上翻/下翻一页。 |
| `gg`、`G` | 滚动到列表首页/末页。 |

交互命令仅接受 ASCII 字符，`N` 必须为仅含 `0`–`9` 的正整数。曲目名和路径可包含 Unicode 字符。

#### 示例

提取、裁剪或创建音频：

```bash
siglus-ssu -s --x /path/to/voice/z0001.ovk /path/to/ogg_out/
siglus-ssu -s --x /path/to/bgm/ /path/to/trimmed/ --trim /path/to/Gameexe.dat
siglus-ssu -s --c /path/to/translated_ogg/ /path/to/audio_out/
```

比较语音归档，或预览 BGM 播放列表：

```bash
siglus-ssu -s --a /path/to/old/z0001.ovk /path/to/new/z0001.ovk
siglus-ssu -s --play /path/to/BGM/
```

---

### `-v` / `--video` — 处理 `.omv` 视频文件

提取会复制内嵌的 Ogg 流，包括音频。创建只包装首个 Theora 流，无需重新编码。缺页、页不完整或校验和错误都会导致操作失败。

#### 语法

```
siglus-ssu -v --x <input_dir | input_file.omv> <output_dir>
siglus-ssu -v --a <input_file.omv>
siglus-ssu -v --c <input_ogv> <output_omv | output_dir> [--refer ref.omv] [--mode N] [--flags N]
```

| 参数 | 说明 |
|---|---|
| `--x` | 提取 `.ogv`，目录输入会递归扫描并保留子目录。 |
| `--a` | 显示文件头、帧及可用的 Theora 流信息。 |
| `--c` | 包装 Theora 流，输入像素平面须已符合所选模式。 |
| `--refer <ref.omv>` | 复制参考文件的模式和逐帧 flags，显式 `--mode`、`--flags` 可覆盖，不复制视频数据。 |
| `--mode N` | 设置像素解释模式，不转换像素，支持十进制或十六进制。无参考时默认 `2`。 |
| `--flags N` | 设置原始逐帧 flags，通常保留 `0`。使用 `0x1A2B3C00` 等原位值，或 `0-9:0x1A2B3C00,10-:0x00000000` 等区间写法。低 8 位自动生成。 |

创建时，已存在的目录、以分隔符结尾或不带扩展名的输出均按目录处理。指定输出文件时请使用 `.omv` 扩展名。

覆盖现有文件需要在 `Overwrite? [y/N]` 提示后输入 `y` 或 `yes`。收到拒绝覆盖的答复，或遇到转换期间才创建的目标文件时，命令会保留该文件并报错。构建索引后的 Theora 数据变动会导致 OMV 创建失败。批量提取会继续处理其他文件。

#### 像素布局与 `.ogv` 输入

用 `-v --a` 记录原 OMV 的模式。提取的 Ogg 不包含模式信息。以下布局使用完整尺寸的 Theora 4:4:4 平面。

| 模式 | 布局 |
|---|---|
| `0` | B、G、R 平面，不透明。 |
| `1` | B、G、R 平面，每个平面后附一段 alpha。 |
| `2` | 全范围 BT.601 Y、U、V。 |

模式 `1` 的可见高度为 `H` 时，Theora 图像高度需为 `H + ceil(H / 3)`。每个平面的前 `H` 行存放颜色，后续 alpha 段按平面顺序拼接，并取前 `H` 行作为透明度。1080 行可见图像需要编码为 1440 行。

普通播放器按 YUV 解释平面。模式 `0` 和 `1` 须重建颜色或透明度后才能正常播放。`--mode` 和 `--refer` 设置像素解释方式。请按目标布局编码输入 Ogg。

普通不透明 SDR 视频可用带 `libtheora` 的 FFmpeg 准备模式 `2` 输入：

```bash
ffmpeg -i input_video -map 0:v:0 -an -vf "scale=out_range=full:out_color_matrix=bt601,format=yuv444p" -c:v libtheora -q:v 8 -color_range pc output.ogv
siglus-ssu -v --c output.ogv output.omv --mode 2
```

输入颜色元数据缺失或错误时，请通过 scale 的 `in_range` / `in_color_matrix` 修正。本例不保留音频或透明度。

#### 示例

```bash
siglus-ssu -v --x /path/to/movie/ /path/to/ogv_out/
siglus-ssu -v --a /path/to/op.omv
siglus-ssu -v --c /path/to/translated.ogv /path/to/translated.omv --refer /path/to/original.omv
```

---

### `-p` / `--patch` — 修改 `SiglusEngine.exe`

修改引擎密钥、语言设置或地区检测。默认生成新程序，`--inplace` 会覆盖原文件。

#### 语法

```bash
siglus-ssu -p --altkey <input_exe> <input_key> [-o output_exe] [--inplace]
siglus-ssu -p --lang (cjk | cjk-path | config.json) <input_exe> [-o output_exe] [--inplace] [--allow-partial] [--revert]
siglus-ssu -p --info <input_exe>
siglus-ssu -p --loc (0 | 1) <input_exe> [-o output_exe] [--inplace]
```

| 参数 | 说明 |
|---|---|
| `<input_exe>` | 引擎程序，不接受符号链接输入或输出路径。 |
| `<input_key>` | 仅用于 `--altkey`，接受 `key.txt`、`暗号.dat`、`SiglusEngine*.exe`、`Scene.pck` 文件或 `key=bytes` / `angou=text` 字面量，不接受目录。输出不能指向密钥文件。 |
| `-o`、`--output` | 指定输出程序。默认后缀为 `_alt.exe`、`_CJK.exe`、`_CJKPATH.exe`、`_LOC0.exe` 或 `_LOC1.exe`，JSON 使用 `_<CONFIG>.exe`，还原使用 `_ORIGINAL.exe`。 |
| `--inplace` | 覆盖输入，不能与 `-o` 同用。 |
| `--lang cjk` | 设置 CJK 字体字符集、区域 `chinese` 和语言代码 `zh`，保留游戏文件及存档路径。 |
| `--lang cjk-path` | 在 `cjk` 基础上改用 `GameexeZH.dat`、`SceneZH.pck` 和 `savedata_zh`。 |
| `--lang config.json` | 从 JSON 文件读取全部六项配置，也可传入一个加引号的 JSON 对象。输出不能覆盖配置文件。 |
| `--allow-partial` | 即使部分配置不可用，也应用支持的语言补丁。默认必须全部支持才会写出。 |
| `--revert` | 从先前语言补丁还原字节一致的原程序，须与 `--lang` 同用，不能与 `--allow-partial` 同用。 |
| `--info` | 查看可修改的密钥、语言和地区设置，不写文件。 |
| `--loc 0` | 禁用地区检测。 |
| `--loc 1` | 恢复由本工具 `--loc 0` 修改过的 EXE 的区域检测。 |

#### 语言配置

JSON 必须包含全部六个字段：

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

已打过语言补丁的引擎可直接改为其他配置。`charset` 常用值为 `0`（ANSI）、`128`（Shift-JIS）和 `134`（GB2312）。CJK 预设会将识别到的日文/CJK 字体位置改为 `134`，不受支持的引擎会失败，除非使用 `--allow-partial`。

#### 示例

```bash
siglus-ssu -p --info /path/to/SiglusEngine.exe
siglus-ssu -p --altkey /path/to/SiglusEngine.exe /path/to/key.txt -o /path/to/patched.exe
siglus-ssu -p --lang cjk-path /path/to/SiglusEngine.exe
siglus-ssu -p --lang config.json /path/to/SiglusEngine.exe
siglus-ssu -p --lang config.json --revert /path/to/SiglusEngine_CONFIG.exe
siglus-ssu -p --loc 0 /path/to/SiglusEngine.exe
```

---

### `test` — 回编测试

提取并重建一个 PCK 或目录当前层的全部 `.pck`，检查字节或规范化 payload 是否一致。目录输入会逐个处理，并在失败后继续。临时文件会在结束后清理。

默认使用内嵌原始源码。未声明源码区段的 PCK 会被跳过，已声明但不可读或为空的源码区段会导致失败。

#### 语法

```bash
siglus-ssu [--const-profile N] test [--serial] [--report-json FILE] <input_pck|input_dir>
siglus-ssu --const-profile N test --allow-invalid [--serial] [--report-json FILE] <input_pck|input_dir>
siglus-ssu --const-profile N test --decompile [--serial] [--report-json FILE] <input_pck|input_dir>
```

| 选项 | 说明 |
|---|---|
| `--decompile` | 不依赖内嵌源码，重建源码、回编并比较 payload。必须显式指定全局 profile，使用严格 UTF-8，不重试其他设置。 |
| `--allow-invalid` | 在指定 profile 的源码回编模式下，按 UTF-8 替换非法字节，不可用于 `--decompile`。 |
| `--serial` | 禁用回编阶段的并行编译。 |
| `--report-json FILE` | 将结果和耗时写入 JSON。也可写作 `--report-json=FILE`。报告不能覆盖输入 PCK 或用于读取密钥的文件。 |

显式 `--const-profile` 仅按该 profile 尝试一次，除 `--allow-invalid` 外均正常检测源码编码。未显式指定时，源码回编会先尝试 profile `0`–`10`，必要时再以 UTF-8 替换解码重试。显式字符串乘数用于全部尝试。

#### 结果

| 状态 | 含义 |
|---|---|
| `EXACT` | 回编 PCK 字节完全一致。 |
| `PAYLOAD_SAME` | 规范化 payload 一致，反编译回测成功时始终使用此状态。 |
| `FAIL` | 重建失败或 payload 不一致，包括 `text_only` 和不完整结果。 |
| `SKIP` | 源码回编模式下未声明内嵌源码。 |

至少一个文件通过且没有失败时，命令返回 `0`。任一失败或全部跳过时返回 `1`。摘要会显示耗时及失败文件。

JSON 包含 `decompile` 标记和 `results`。每个结果包含 `path`、`status`、`detail`、`elapsed`、`timings`、`profile`、`allow_invalid` 和 `compile_backend`（`rust` 或 `python`）。失败或跳过时，最后三项为 `null`。

```bash
siglus-ssu test /path/to/Scene.pck
siglus-ssu test --report-json /path/to/results.json /path/to/pck_dir/
siglus-ssu --const-profile 2 test --allow-invalid /path/to/Scene.pck
siglus-ssu --const-profile 0 test --decompile /path/to/Scene.pck
```

<a id="siglusss-language-spec"></a>

## SiglusSS 语言规范

两种编译后端都按所选[常量 profile](#常量-profile)解析 form、内建成员和命令签名。具体定义见 [const.py](src/siglus_ssu/const.py) 中的 profile 表。

### 源文件与预处理

每个场景对应一个 `.ss` 文件。编译器按文件名折叠 ASCII 大小写后的顺序读取同目录的全局 `.inc` 文件。默认逐文件检测编码，也可用 `--charset` 指定。编译器去掉开头的 BOM 字符，将 CRLF 和 CR 统一为 LF，读到首个 DOS EOF 字符（U+001A）时停止。可用 `--allow-invalid` 替换无法解码的字节。

编译器先载入全局声明，再处理各场景。

1. 删除注释，将引号外的 ASCII 大写字母转为小写。
2. 处理条件指令，收集 `#inc_start` 与 `#inc_end` 之间的局部声明。
3. 处理局部声明，展开剩余场景文本中的替换项。
4. 分词、解析语法、检查 form、生成字节码，再链接同目录各场景中的全局命令。

`;` 和 `//` 开始行注释。`/* ... */` 删除块内内容并保留换行，不支持嵌套。删除块注释后，两侧文本可以直接拼接。`/*/` 也表示空块注释。引号内的注释标记按字面内容处理。块注释未闭合时报错。

首行以 `// #SCENE_SCRIPT_ID = ` 开头，紧接四位 ASCII 数字时，编译器会取这四位数字作为场景 ID，忽略首行余下内容。

#### 条件指令与场景局部声明

```text
#ifdef name
#elseifdef name
#else
#endif
```

`#ifdef` 和 `#elseifdef` 检查 include 名称是否已登记。待查名称以 ASCII 字母、CP932 双字节字符、`_` 或 `@` 开头，后续也可包含 ASCII 数字。条件最多嵌套 15 层。文本是否纳入仅由最内层条件决定。内层条件为真时，外层条件为假的区域也可纳入内层文本。

`.ss` 中的条件可访问全局 include 名称。编译器在登记场景局部名称前处理这些条件。`.inc` 中的条件指令写在声明文本内，可查询收集该段文本时已登记的名称。

`#inc_start` 开始收集局部声明，`#inc_end` 恢复处理场景正文。收集期间重复写 `#inc_start` 也只需一次 `#inc_end`。在区域外写 `#inc_end` 或在文件结束前缺少结束标记都会报错。

### 词法

空格、制表符和换行用于分隔 token。语句可跨行书写，也可在同一行写多条。语法中的花括号表示重复，方括号表示可选，引号表示字面 token。`ascii-letter` 指大小写折叠后的 `a`–`z`，`digit` 指 `0`–`9`，`hex-digit` 还包括 `a`–`f`。

```text
identifier ::= id-start { id-start | digit }
id-start   ::= "_" | "$" | "@" | ascii-letter
label      ::= "#" { "_" | ascii-letter | digit }
decimal    ::= digit { digit }
integer    ::= decimal | "0b" { "0" | "1" } | "0x" { hex-digit }
```

保留字

```text
command  property  goto  gosub  gosubstr  return
if  elseif  else  for  while  continue  break  switch  case  default
```

z-label 写作 `#z` 加一至三位数字，须满足所选 profile 的数值上限。Profile `7` 和 `8` 的上限为 `100`，其他 profile 的上限为 `1000`，均不含上限。其余符合 `label` 的写法是普通标签，例如 `#` 和 `#z1234`。z-label 按数值占用槽位，`#z1` 和 `#z01` 不能同时定义。引用按折叠 ASCII 大小写后的完整拼写匹配。每个场景必须定义编号 `0`。标签不可在同一场景重定义，引用也必须在该场景内解析。

整数字面量按有符号 32 位整数回绕。正负号是一元运算符。单独的 `0b` 和 `0x` 表示零。单引号字面量转义后只能有一个字符，取该字符的编号作为 `int` 值。双引号字面量的 form 为 `str`。直接写在 `.ss` 中的字面量须占同一物理行。

| 转义 | 单引号 | 双引号 |
| --- | --- | --- |
| `\\` | 反斜杠 | 反斜杠 |
| `\n` | 字符 `n` | LF |
| `\'` | 单引号 | — |
| `\"` | — | 双引号 |

在 Windows CP932 中编码为两个字节的连续字符可直接写成裸字符串。`【` 和 `】` 是界符。要在一个字符串 token 中包含其他字符、空格或标点，可用双引号。

### Include 声明

全局 `.inc` 文件和场景局部声明区使用同一套声明语法。

```text
inc-file ::= { declaration }
declaration ::= ("#replace" | "#define" | "#define_s") name text
              | "#macro" macro-name ["(" parameter {"," parameter} ")"] text
              | "#property" name [":" form-name ["[" decimal "]"]]
              | "#command" name ["(" inc-arg {"," inc-arg} ")"] [":" form-name]
              | "#expand" text

parameter ::= parameter-name ["(" default-text ")"]
inc-arg   ::= form-name ["(" default-literal ")"]
```

| 声明 | 名称结束位置 |
| --- | --- |
| `#replace`、`#define` | 空格、制表符或换行 |
| `#define_s` | 制表符或换行，名称可含空格 |
| `#macro` | 空格、制表符、换行或 `(`。名称以 `@` 开头。 |
| `#property` | 空格、制表符、换行或 `:` |
| `#command` | 空格、制表符、换行、`(` 或 `:` |

场景局部 include 声明与可见的全局 include 声明共用名称空间。编译器拒绝重名。在场景中直接引用的名称也须符合场景标识符语法。

#### 文本替换与宏

编译器跳过声明文本开头的空白，在纳入文本中的下一个未转义 `#` 或文件末尾停止读取。换行转为空格，末尾空格和制表符会去掉。声明文本中的字面 `#` 写作 `##`，引号内也采用同样写法。

`#replace` 插入文本后从插入内容末尾接着扫描。`#define` 和 `#define_s` 会重新扫描插入内容。替换在分词前按字符匹配，引号内也会匹配。每张替换表优先选最长的匹配名称。定义和宏参数同时匹配时，采用按字典序较大的名称。同名时采用参数。

宏的实参写在紧跟宏名的圆括号内。只写宏名或写 `()` 都表示零个实参。省略末尾实参时须有非空默认值。实参以引号和嵌套圆括号之外的逗号分隔。空项和多余项都会报错。声明零参数宏时省略参数表。参数默认值在第一个 `)` 处结束，不能含制表符或换行。

编译器先展开实参和默认值，再用所得值替换参数并展开宏体。参数重名时采用第一次出现的值。后续同名参数仍须有实参或默认值。宏体展开后从插入内容末尾接着扫描。

`#expand` 会立即展开文本，再将结果作为 include 声明读取。替换项和宏在收集时登记。编译器先收集 `#property` 和 `#command` 的文本，再展开并登记，每个 include 内先登记属性，再登记命令。全局 include 全部收集完毕后才开始登记属性和命令。

宏最多嵌套 128 层。文本展开连续超过 10,000 个扫描步骤未使剩余长度低于此前最小值时停止。`#expand` 在处理声明时采用同样的限制，按声明计步。

#### 属性与命令签名

- `#property` 默认为 `int`，不接受 `void`。方括号尺寸仅用于 `intlist` 和 `strlist`，填写无符号的十进制数字。
- `#command` 的返回 form 默认为 `int`。参数表只写 form。零参数时省略圆括号。
- `int` 默认值用十进制写法，可在数字前紧接 `+` 或 `-`。`str` 默认值用双引号字面量。从第一个带默认值的参数开始，后续参数都须有默认值。编译器会补齐省略的 `int` 实参。即使声明中写了 `str` 默认值，调用时也须显式传入字符串实参。

### 场景语法

```text
scene         ::= { statement }
statement     ::= label-target | command-def | property-def | jump | return-stmt
                | if-stmt | for-stmt | while-stmt | "continue" | "break"
                | switch-stmt | element-expr [assign-op expr]
                | "【" string-token "】" | string-token

command-def   ::= "command" identifier [ "(" [property-def {"," property-def}] ")" ]
                  [":" form] block
property-def  ::= "property" identifier [":" form]
form          ::= form-name ["[" expr "]"]
block         ::= "{" { statement } "}"
jump          ::= "goto" label-target | ("gosub" | "gosubstr") [args] label-target
label-target  ::= label | z-label
return-stmt   ::= "return" ["(" expr ")"]

if-stmt       ::= "if" "(" expr ")" block {"elseif" "(" expr ")" block} ["else" block]
for-stmt      ::= "for" "(" {statement} "," expr "," {statement} ")" block
while-stmt    ::= "while" "(" expr ")" block
switch-stmt   ::= "switch" "(" expr ")" "{" {case-clause} [default-clause] "}"
case-clause   ::= "case" "(" expr ")" {statement}
default-clause ::= "default" {statement}

expr          ::= unary {binary-op unary}
unary         ::= {"+" | "-" | "~"} primary
primary       ::= "(" expr ")" | "[" expr {"," expr} "]" | jump
                | integer | character-literal | string-token | label | element-expr
element-expr  ::= element {"." element | "[" expr "]"}
element       ::= identifier [args]
args          ::= "(" [arg {"," arg}] ")"
arg           ::= [identifier "="] expr
```

同级二元运算符从左到右结合。下表按优先级从低到高排列。

| 级别 | 运算符 |
| --- | --- |
| 1 | `\|\|` |
| 2 | `&&` |
| 3 | `\|` |
| 4 | `^` |
| 5 | `&` |
| 6 | `==`, `!=` |
| 7 | `>`, `>=`, `<`, `<=` |
| 8 | `<<`, `>>`, `>>>` |
| 9 | `+`, `-` |
| 10 | `*`, `/`, `%` |

前缀运算符的优先级高于所有二元运算符。Profile `7` 将 `&&` 和 `||` 同列为第 1 级。逻辑运算会求值两个操作数。列表字面量的 form 为 `list`，至少含一个表达式。给列表实参加圆括号不会改变 form 或长度，例如 `wipe(option=([1,2]))`。

赋值语句使用以下运算符。

```text
=  +=  -=  *=  /=  %=  &=  |=  ^=  <<=  >>=  >>>=
```

### Form 与名称解析

未限定的元素名按调用、场景、全局的顺序查找。调用名称空间包含参数和局部 `property`。场景名称空间包含场景局部 include 声明及场景命令。全局名称空间包含全局 include 声明和所选 profile 的内建元素。成员按前一段的 form 查找。下标要求前一段有可索引成员，并使用 `int` 或 `intref` 表达式。

表达式中无法解析的单段名称会转为折叠 ASCII 大小写后的字符串。名称不可含 `@` 或 `$`，也不可带实参。普通标签在表达式中的 form 为 `label`。z-label token 用在标签定义和跳转目标中。

元素链末尾为 `int`、`str`、`intlist` 或 `strlist` 属性时，整条元素链的 form 分别为引用类型 `intref`、`strref`、`intlistref` 或 `strlistref`。元素链直接作为语句使用时，末尾须是命令。

#### 运算和赋值

| 操作数 | 运算符与结果 |
| --- | --- |
| 一个 `int` 或 `intref` | 前缀 `+`、`-`、`~` 得到 `int`。 |
| 两个 `int`/`intref` | 优先级表中的全部二元运算得到 `int`。 |
| 两个 `str`/`strref` | `+` 得到 `str`。`==`、`!=`、`>`、`>=`、`<`、`<=` 得到 `int`。 |
| 左侧 `str`/`strref`，右侧 `int`/`intref` | `*` 得到 `str`。 |

普通赋值给 `intref` 或 `strref` 时，可传入对应的值或引用。其他可赋值 form 要求两侧一致。复合赋值应用二元运算后再赋值。例如 `s[0] *= 3` 就地重复字符串。

比对参考版本的 Siglus 官方编译器时，`s[0] *= 3` 在两种编译器中都会写出各操作数对应的 form。参考版本生成 `s[0] * 3` 这类二元表达式时会两次写入左操作数的 form。

#### 声明与调用规则

- 场景 `property` 的 form 和 `command` 的返回 form 默认为 `int`。Profile `6`–`8` 允许在命令外声明调用局部属性。其他 profile 要求写在命令体内。命令定义结束时会清空调用名称空间并退出命令上下文，嵌套命令定义也一样。
- 属性或参数 form 后的方括号表达式须为 `int`。`intlist` 和 `strlist` 在运行时取该表达式的值作长度，省略时取零。命令的返回 form 只由 form 名决定。
- 全局 `.inc #command` 在同目录内必须有且仅有一个定义，未使用的命令也一样。定义的返回 form、参数数量和各位置的参数 form 必须匹配声明。场景局部 `#command` 必须在同一场景内定义，调用时采用该声明的签名。
- 实参须符合所选命令签名。`int`、`str` 值参数可接受对应的标量引用。引用参数须传入引用。命名实参须使用已定义的名称，并匹配 form。编译器先排位置实参，再排命名实参，两组各自保留原顺序。Profile `8` 的 `wipe(key_skip=...)` 和 `mask_wipe(key_skip=...)` 保留整数引用。
- 调用表达式采用声明的返回 form。编译器检查 `return(expr)` 中的表达式，不核对表达式的 form 与声明的返回 form 是否相同。

#### 控制流与对话

- `if`、`elseif`、`for` 和 `while` 的条件须为 `int` 或 `intref`。带 `case` 的 `switch` 在整数类或字符串类内比较。运行时只求值一次条件，执行首个匹配的 `case`，找不到匹配时执行可选的 `default`。分支执行完即退出 `switch`。`break` 和 `continue` 的目标为循环。
- `goto`、`gosub` 和 `gosubstr` 作为表达式时，form 分别为 `void`、`int` 和 `str`。需要反汇编或反编译时，`gosub` 和 `gosubstr` 的各实参应为整数或字符串。
- 编译器禁止在条件、`case` 表达式、命令实参、作为独立语句的子程序调用实参及下标表达式中使用所选 profile 的选择命令。选择命令见 [profile 表](#常量-profile)。
- 独立的字符串语句显示正文并分配一个已读 flag。`【 string-token 】` 显示说话人名。部分内建命令也按所选 profile 分配 flag。
- 语法嵌套超过 64 层或表达式树高度超过 128 时，编译器和 LSP 会发出警告。宏展开有单独的硬限制。

### 示例

`names.inc` 声明命令和整数默认值。

```text
#define title "ABC"
#command repeat_name(int(3)) : void
```

`main.ss` 调用并定义该命令。

```text
#z0
repeat_name()

command repeat_name(property count : int) : void {
    s[0] = title
    s[0] *= count
    set_namae(s[0])
}
```
