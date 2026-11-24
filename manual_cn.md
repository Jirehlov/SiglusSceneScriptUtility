# SiglusSceneScriptUtility 使用手册

> **仅支持 CLI：** 本项目只支持 `siglus-ssu` 命令行接口，不支持直接导入或调用模块，也不对由此产生的任何问题负责。

**版本：** 0.5.8

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
5. [SiglusSceneScript 语言参考](#siglusss-language-spec)
6. [提示与故障排除](#提示与故障排除)

---

## 概述

SiglusSceneScriptUtility（命令名 `siglus-ssu`）是用于处理 SiglusEngine 游戏文件的命令行工具，支持：

- 编译、提取、反汇编和反编译场景脚本。
- 导出和应用译文、修改存档、分析游戏数据。
- 提取和重建图片、音频、视频，以及按角色收集语音。
- 修改引擎密钥和语言设置。
- 通过 LSP 提供编辑器支持。

处理场景脚本时，请选择对应作品的[常量 profile](#常量-profile)。未受支持的引擎变体可能使用不同格式。

---

## 安装

### 方式一：从 PyPI 安装

需要 Python 3.12 或更高版本：

```bash
pip install siglus-ssu
```

兼容的平台 wheel 包含 Rust 加速。其他平台可使用速度较慢的纯 Python wheel，或从源码构建以启用原生加速。安装后无需初始化或单独下载常量表。

### 方式二：从源码安装

需要 Python 3.12+、[uv](https://github.com/astral-sh/uv) 和 [Rust 1.88+](https://rustup.rs/)。

克隆仓库后，在仓库根目录运行：

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

全局选项可放在模式之前或之后，但必须放在 `--` 之前。也支持 `--const-profile=N` 和 `--string-xor-multiplier=N` 写法。

### 常量 profile

各 profile 包含不同的内建类型、元素编号、命令签名和编译规则。下表逐行列出相对参考 profile 的差异，未说明的编译规则保持一致。作品名仅作为兼容示例。

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

Profile 编号不表示版本先后。反汇编、反编译、编译和 payload 比较时，请使用相同的 profile。对于包含内嵌源码的 PCK，可运行 `siglus-ssu test Scene.pck`，从成功结果中查看适用的 profile。

Profile `10` 仅覆盖部分移动端接口。`mobile_*` 类型名为内部占位名称，不可作为官方类型用于源码声明。此类对象作为字节码值的用法尚未验证。

### 场景字符串 XOR 乘数

仅在作品的场景字符串编码不同于 profile 默认值时使用 `--string-xor-multiplier N`。`0` 表示明文 UTF-16LE 字符串。本选项不改变压缩、外层加密或引擎程序；`--no-angou` 也不会关闭场景字符串 XOR。

解码、修改和回编同一作品时，请保持 profile 和乘数一致。提取目录中不保存这些设置。错误的乘数可能产生乱码，且不一定触发格式错误。一次命令会将同一乘数用于全部场景及两个比较输入，因此采用不同乘数的输入需要分别分析。

修改乘数后，`-c --tmp` 缓存中的全部场景都会重新编译。普通提取、`--dat-repack`、`--gei` 等不处理场景字符串的操作会忽略本选项。

明文场景字符串作品的用法：

```bash
siglus-ssu --string-xor-multiplier 0 -x --disam /path/to/Scene.pck
siglus-ssu --string-xor-multiplier 0 -m /path/to/extracted/chapter1.dat
siglus-ssu --string-xor-multiplier 0 -m --apply /path/to/extracted/chapter1.dat
siglus-ssu --string-xor-multiplier 0 -c /path/to/source/ /path/to/translated.pck
```

### 命令别名

`siglus-ssu help` 和 `siglus-ssu version` 分别等同于 `--help` 和 `--version`。

选择模式及必需的子操作后，可用 `--` 分隔以 `-` 开头的位置参数，例如 `siglus-ssu test -- --sample.pck`。所有选项必须放在 `--` 之前。对于以 `-` 开头的选项值，请使用绝对路径或加上 `./` 前缀。

长选项需完整输入，不支持任意前缀缩写。

### 获取帮助

```bash
siglus-ssu --help
```

各模式下的 `--help` 均显示同一份全局帮助。

---

## 模式参考

### `-lsp` — 启动语言服务器

通过标准输入输出为 `.ss` 和 `.inc` 文件提供语言服务。请在编辑器的 LSP 客户端中配置以下启动命令：

```bash
siglus-ssu -lsp [--serial] [--read-sav /path/to/read.sav]
```

| 选项 | 说明 |
|---|---|
| `--serial` | 串行扫描工作区，默认并行扫描。 |
| `--read-sav PATH` | 在悬停说明中显示存档已读状态，支持此协议的客户端也可查看或修改单个 flag。存档缺失或无法读取时也可启动服务。 |

支持诊断、语义高亮、补全、悬停说明、定义与引用查找、重命名和文档符号。分析范围包括当前场景及同目录 `.inc` 文件，也包括编辑器中未保存的修改。请像编译时一样选择对应作品的全局 `--const-profile`。

使用推送诊断时，服务器会在编辑期间更新文件内的诊断，并沿用最近一次链接检查的结果。服务器会在打开或保存源文件时重新检查链接，关闭带有未保存修改的源文件时也会重新检查。客户端主动请求诊断时，服务器会按当前工作区检查。

工作区索引会跨会话缓存，并在不兼容时重新生成。可用 `SIGLUS_SSU_LSP_CACHE_DIR` 更改缓存位置，默认位置为：

- Windows：`%LOCALAPPDATA%\siglus_ssu\lsp-index`，缺失时使用 `%APPDATA%\siglus_ssu\lsp-index`。
- 其他平台：`$XDG_CACHE_HOME/siglus_ssu/lsp-index`，缺失时使用 `~/.cache/siglus_ssu/lsp-index`。

#### 已读 flag

已读 flag 在每个场景内从 `0` 编号。存档中的零值表示未标记已读，对应内容可能已在等待、清屏等标记提交操作之前显示过。

场景名及 flag 数量与当前源码匹配时，服务才会显示存档状态。数量不匹配时仅报告问题，不应用存档状态。悬停说明对应生成 flag 的文本、命令或宏调用，同一位置可能对应多个 flag。

客户端可在 `siglus/readFlags` 请求中带上上次收到的 `mappingId` 和 `saveRevision`，复用已取得的源码范围。源码映射相同、存档有变化时，客户端会在 `states` 字段收到以 base64 编码的场景 flag 字节。两者均未变化时，响应会省略范围数据与状态字节。客户端负责绘制高亮和监视文件，可在存档变动后传入 `verifySave: true` 重新核对文件内容。

服务声明支持 `experimental.siglusReadFlags.setReadFlag` 时，客户端可发送 `siglus/setReadFlag`，在 `textDocument` 中传入已打开文档的 URI 和版本，并传入当前 `mappingId`、flag 编号 `index` 及布尔值 `read`。服务会更新选定 `read.sav` 中对应的 flag，并在替换文件前核对原存档内容。遇到源码映射过期、场景缺失或 flag 数量不符时，服务会保留原存档。

客户端可根据服务声明的 `experimental.siglusReadFlags.setReadFlags` 能力发送 `siglus/setReadFlags`，传入相同的 `textDocument`、`mappingId`、`read` 字段和包含 flag 编号的非空数组 `indices`。服务会先校验全部编号，再去重并一次写回指定状态。客户端在成功响应中会收到更新后的计数、`saveRevision` 和写入前的 `previousRevision`。

---

### `-c` / `--compile` — 编译脚本

将 `.ss` 源文件及同目录 `.inc` 声明编译为 `.pck`。源码扫描仅限输入目录当前层，不包含子目录。回编提取出的文件时，请保留 `.scene.ss`、`.defs.inc` 等以点号开头的源码。

#### 语法

```
siglus-ssu -c [options] <input_dir> <output_pck | output_dir>
siglus-ssu -c --gei <input_dir | Gameexe.ini> <output_dir>
siglus-ssu -c --test-shuffle [seed0] [--csv <seed_csv>] <input_dir> <output_pck | output_dir> <test_dir>
```

#### 参数

| 参数 | 说明 |
|---|---|
| `<input_dir>` | 至少包含一个有场景名的 `.ss` 文件的目录，以及所需的 `.inc`、`Gameexe.ini` 和 `暗号.dat`。`--dat-repack` 和 `--gei` 不要求存在 `.ss`。 |
| `<output_pck \| output_dir>` | 已存在的目录或以 `/`、`\` 结尾的路径会接收 `Scene.pck`，其他路径按精确的输出文件名处理。 |
| `--debug` | 编译后保留中间文件。不能与 `--tmp` 同用。 |
| `--charset ENC` | 统一指定源码编码，默认逐文件检测 UTF-8 或 CP932，并根据 BOM 识别 UTF-16 和 UTF-32。`sjis`、`shift_jis` 等 Shift-JIS 别名均使用 Windows CP932。其他 Python 编码需显式指定。 |
| `--allow-invalid` | 将非法输入字节替换为 U+FFFD，也适用于 `Gameexe.ini` 和 `暗号.dat`。未指定编码且没有 UTF-16 或 UTF-32 BOM 时，会先严格尝试 UTF-8 和 CP932，均失败后按 UTF-8 替换。语法和类型错误仍会导致失败。 |
| `--no-os` | 不嵌入原始源码，不改变脚本的加密或压缩。 |
| `--dat-repack` | 直接打包现有场景 `.dat`。遇到损坏的场景时，程序会终止回包并保留已有 PCK。仅 `Gameexe.dat` 和 `暗号.dat` 可作为辅助文件跳过。同目录 `.inc` 用于提供包级命令元数据，缺失时会打印警告。可用 `--charset` 或 `--allow-invalid` 解码文本输入。回包时优先使用有效的 `key.txt`，其次是 `暗号.dat`。也支持 `--no-os` 和 `--no-lzss`。 |
| `--no-angou` | 禁用 LZSS 压缩、外层 XOR 加密和原始源码嵌入，不关闭场景字符串 XOR。不能与 `--tmp` 同用。 |
| `--no-lzss` | 禁用 LZSS 压缩和原始源码嵌入，保留脚本加密。不能与 `--tmp` 同用。 |
| `--serial` | 依次编译场景脚本。打包可以使用多个工作线程。 |
| `--max-workers N` | 场景并行编译的最大工作数，必须为正整数。默认每阶段使用可用 CPU 数的一半，限制为 1–16。自动分配线程的全量编译中，Rust 后端可以让编译和压缩共用两个阶段分配的线程。Windows 上的 Python 编译最多接受 61。与 `--serial` 同用时无效。 |
| `--set-shuffle SEED` | 设置字符串表乱序种子（`0`–`0xFFFFFFFF`，十进制或十六进制，默认 `1`），并启用串行编译。不能与 `--tmp` 同用。 |
| `--tmp <tmp_dir>` | 复用指定目录进行增量编译。串行构建从首个变化的场景开始重新编译，以保持字符串表顺序。并发构建需要各用一个缓存目录。不能与 `--debug`、`--dat-repack`、`--no-angou`、`--no-lzss`、`--set-shuffle`、`--test-shuffle`、`--csv`、`--gei` 或全局 `--const-profile` 同用。 |
| `--test-shuffle [seed0]` | 从 `seed0`（默认 `0`）搜索至 `0xFFFFFFFF`，找到任意一条与 `<test_dir>` 中全部参考 DAT 的字符串索引匹配的连续种子链。程序按固定的 Windows 文件名大小写映射查找同名 DAT，优先选用拼写完全一致的文件。可选种子后必须保留三个路径参数。省略种子时，可用 `--set-shuffle` 的值作为搜索起点。不能与 `--tmp` 或 `--gei` 同用。 |
| `--csv <seed_csv>` | 与 `--test-shuffle` 同用时，随链接后的 PCK 一并发布各场景的初始和最终种子。目录目标下的文件名为 `test_shuffle_seeds.csv`。 |
| `--gei` | 仅将 `Gameexe.ini` 编译为 `Gameexe.dat`，输出始终按目录处理。缺少 INI 时会警告并成功结束，不创建 `Gameexe.dat`。不能与 `--tmp` 或 `--test-shuffle` 同用。 |

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

- **源码编码：** 仅在复现按 UTF-8 替换解码得到的历史产物时使用 `--charset utf8 --allow-invalid`，否则可能保留乱码。编译在首个 DOS EOF 字符（U+001A）处停止，并忽略后续字节。字面量与字符规则见[语言参考](#siglusss-language-spec)。
- **密钥兼容性：** 从 `暗号.dat` 或 `angou=text` 派生的密钥使用 CP932，可能与官方 Windows 转换结果不同。处理现有官方文件时，优先使用原始 16 字节密钥或对应引擎程序。普通编译时请将原始密钥写入 `key.txt`，并移走输入目录中优先级更高的 `暗号.dat`。
- **增量编译：** 场景源码有改动，或对应的 DAT、LZSS 缓存文件缺失或有改动时，程序会重新编译该场景。增删改 `.inc`、更改编译设置或升级程序后，可能需要全量重编译。场景缓存更新失败或中断后，下次运行会全量重建。嵌入原始源码时，打包也会复用未修改文件的压缩加密数据。
- **乱序搜索：** 字符串表顺序不影响普通翻译工作。找不到匹配全部场景的种子链时，命令会在发布 PCK 和 CSV 前返回失败。把报告中的首场景起始种子传给 `--set-shuffle` 即可复现该种子链。
- **路径与名称：** 路径按所在文件系统的规则查找。多文件操作会按固定的 Windows 文件名大小写映射检查选中输入路径，并拒绝冲突，例如同一目录内的 `A.ss` 与 `a.ss`；无关目录项不参与检查。程序自动查找文件名时，仅对大小写归约后同名的候选发出警告，按原有顺序选取一份，在内嵌配置源码中也仅保留选中的文件。各命令原有的输出命名规则继续适用。运行时场景名仅将 ASCII `A`–`Z` 转为小写，内嵌源码文件名保留原拼写。

#### 编译统计

编译结束时会显示各阶段耗时及文件数。编译与场景压缩的计时区间可能重叠。`scene_files` 为场景总数，`compiled_scene_files` 为本次重建数。普通全量编译还会显示源码、已读标记和二进制大小统计。

---

### `-x` / `--extract` — 提取文件

从 `.pck` 提取已解码的场景 `.dat` 及内嵌原始源码。`--decompile` 可在不依赖内嵌源码的情况下重建 `.ss` / `.inc`。

#### 语法

```bash
siglus-ssu -x [--disam] [--decompile] <input_pck> [output_dir] [--angou <path|angou=text|key=bytes>]
siglus-ssu -x --disam <input_dir> [output_dir] [--angou <path|angou=text|key=bytes>]
siglus-ssu -x --gei <Gameexe.dat | input_dir> [output_dir] [--angou <path|angou=text|key=bytes>]
```

#### 参数

| 参数 | 说明 |
|---|---|
| `<input_pck>` | 要提取的场景 `.pck`，加密场景需要有效的密钥来源。 |
| `<input_dir>` | 与 `--disam` 同用时，扫描当前层的 `.dat`，跳过非场景文件。 |
| `[output_dir]` | 输出基目录，默认为输入文件所在目录或输入目录本身。PCK 提取会创建带时间戳的子目录。 |
| `--disam` | 额外写出 `<scene>.dat.txt` 反汇编，不能与 `--gei` 同用。 |
| `--decompile` | 写出重建的 `decompiled/<scene>.ss`，并按需生成 `decompiled/__decompiled.inc`。同时传入 `--disam` 可生成反汇编文本。需要包含包级元数据的完整场景 PCK，不接受单个 `.dat` 或目录。不能与 `--gei` 同用。 |
| `--angou VALUE` | 指定[解密密钥来源](#解密密钥)。 |
| `--gei` | 从 `Gameexe.dat` 或所在目录还原 `Gameexe.ini`。给定目录时，程序按固定的 Windows 文件名大小写映射查找，并对大小写冲突发出警告。已有同名文件时，依次尝试 `Gameexe_1.ini` 等文件名。 |

在 `Output:` 后打印提取目录。提取 PCK 时，程序会给重名的输出加上数字后缀，并报出不符合目标文件系统规则的文件名。要编辑内嵌源码，请在该目录中修改，再直接将该目录传给 `-c`。

如果场景和包内密钥文件都叫 `暗号.dat`，密钥会提取到 `.siglus-ssu-keys/`。编译和回包时可以从该目录读取密钥。

反编译不会自动检测 profile，也不能还原原始宏、注释或排版。请使用相同的 profile 和字符串乘数回编 `decompiled/`，再用 `-a --payload` 验证。回编后的 PCK 不要求字节完全一致。反汇编不完整时，反编译会失败。

**限制：** 请向 `gosub` 和 `gosubstr` 传递独立的整数或字符串实参。列表字面量实参可能产生无法完整反汇编或反编译的结果。

FlixEngine 场景使用 profile `10`。Flix 资源 PCK 容器仅支持普通提取。

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

请确认没有缺失或新增场景，也没有 payload 差异或不可用结果。仅凭退出状态 `0` 不能判定一致，详见 [payload 比较结果](#payload-比较结果)。

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

`--angou VALUE` 必须为最后一个模式专用选项，并使用独立、非空的值：

| 值 | 含义 |
|---|---|
| 文件路径 | 从 `暗号.dat`、`key.txt`、`Scene.pck` 或 `SiglusEngine*.exe` 读取密钥。 |
| 目录路径 | 搜索该目录当前层文件。 |
| `angou=text` | 从字面量形式的 `暗号.dat` 首行派生密钥。 |
| `key=bytes` | 指定 16 字节密钥，建议使用明确的 `0xNN` 写法，避免数字歧义。 |

解密时先尝试显式密钥来源，再依次尝试包内的 `key.txt` 或 `暗号.dat`、当前目录和父目录。每个目录内按 `Scene.pck`、`Scene*.pck`、`暗号.dat`、`key.txt`、`SiglusEngine*.exe` 的顺序搜索，不递归查找。显式指定路径后不再搜索父目录。显式来源缺失、格式错误或不含密钥时会报错；成功读取的密钥未通过解密校验时，可继续尝试低优先级来源。

编译或解密加密的 `Gameexe.dat` 时，去除注释后的每个非空行都必须是配置赋值，例如 `#WINDOW_XSIZE=640`。配置名可省略 `#` 前缀，以 ASCII 字母、数字或下划线开头，后续可含点号、方括号、连字符、空格和制表符。配置值可含 Unicode 文本。文件格式没有用于区分有效解码结果的校验和。程序用不同密钥解出多份语法有效且内容不同的文本时会报告密钥歧义。

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
| `--type N` | 输出数据库类型（`0`–`2147483647`），默认 `1`。类型 `0` 的字符串必须能以 CP932 编码，其他类型使用 UTF-16LE。 |
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
| `<voice_dir>` | 单个 `.ovk`，或仅扫描当前层 `.ovk` 的目录。 |
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
| `<label>` | 非负十进制数，可带 `z` 或 `#z` 前缀。 |

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
siglus-ssu -g --c [--type N] [--refer <ref_g00 | ref_dir>] <input_png | input_jpeg | input_json | input_dir> [output_g00 | output_dir]
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
| `--refer <ref_g00 \| ref_dir>` | 更新现有 G00。目录输入须指定参考目录。单文件输入可指定参考文件或目录。给定参考目录时，程序按固定的 Windows 文件名大小写映射查找，并对大小写冲突发出警告。省略输出路径时会覆盖选中的参考文件。 |
| `:cutNNN` | 合并时指定 type2 cut，例如 `sprite.g00:cut002`。 |

目录提取和创建仅扫描当前层。生成新的 type2 布局时，程序会校验已有 cut PNG 的可读性和未裁剪尺寸。校验失败时，程序会报错。

#### 创建与更新

不带 `--refer` 时，PNG 默认创建 type0，JPEG 默认创建 type3。创建或更新 type0 时，程序会将 alpha 设为 255。创建 type2 请使用 `--type 2` 和 `.type2.json` 布局，不支持创建 type1。

省略输出路径时，创建结果写在输入旁，更新结果覆盖参考文件。输出须指向不同的文件，不能覆盖源图片、布局文件或其他目标使用的参考图。原地更新时，程序会在替换前核对参考文件的原始内容。更新同一输出目录时，后启动的命令最多等待 30 秒。更新中断后，请先确认没有更新在运行，再删除 `.siglus-g00.lockdir`。

更新前请备份原始资源。JSON 布局不能与 `--refer` 同用。通过参考目录更新单个 cut 时，请将替换图片命名为 `<basename>_cut###.png`。

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

回编多 cut 图片时，请传入 JSON，不要传入单个 cut PNG。提取会保留透明像素下的 RGB，回编直接使用编辑后的 PNG 像素值。

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
- `cuts`：按编号排列，`null` 留空。
- `source`：相对于 JSON 的图片路径，接受 `/` 和 `\` 分隔符。
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

从 OMV 提取 Ogg 视频，或将 Theora 视频包装为 OMV，不重新编码或转换颜色、透明度。提取会保留内嵌音频，创建只保留首个 Theora 视频流。如果 Ogg 流缺页、某页不完整或校验和有误，提取和创建都会报错。

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

请用 `-v --a` 检查原文件，并在提取时记录模式。Ogg 文件不保存 OMV 模式。标准模式使用 Theora 4:4:4 平面：

| 模式 | 布局 |
|---|---|
| `0` | B、G、R 平面，不透明。 |
| `1` | B、G、R 平面，每个平面后附一段 alpha。 |
| `2` | 全范围 BT.601 Y、U、V。 |

模式 `1` 的可见高度为 `H` 时，Theora 图像高度需为 `H + ceil(H / 3)`。每个平面的前 `H` 行存放颜色，后续 alpha 段按平面顺序拼接，并取前 `H` 行作为透明度。1080 行可见图像需要编码为 1440 行。

普通播放器会将平面按 YUV 解释，因此模式 `0`/`1` 需重建颜色或透明度后才能正常观看。`--mode` 和 `--refer` 均不执行该转换。普通 YUV 视频配合模式 `0`/`1` 参考文件会产生错误画面。其他数字模式可作为元数据写入，但不属于上表标准布局。

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
| `--loc 1` | 恢复此前由本工具禁用的地区检测。 |

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
siglus-ssu [--const-profile N] test [--allow-invalid] [--serial] [--report-json FILE] <input_pck|input_dir>
siglus-ssu --const-profile N test --decompile [--serial] [--report-json FILE] <input_pck|input_dir>
```

| 选项 | 说明 |
|---|---|
| `--decompile` | 不依赖内嵌源码，重建源码、回编并比较 payload。必须显式指定全局 profile，使用严格 UTF-8，不重试其他设置。 |
| `--allow-invalid` | 在指定 profile 的源码回编模式下，按 UTF-8 替换非法字节，不可用于 `--decompile`。 |
| `--serial` | 禁用回编阶段的并行编译。 |
| `--report-json FILE` | 将结果与耗时写入 JSON，不允许覆盖输入 PCK 或用于读取密钥的文件。 |

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

## SiglusSceneScript 语言参考

本节说明 `siglus-ssu -c` 接受的源码规则。所选 profile 包含可用类型（`form`）、内建属性和命令，以及对应约束。

### 源文件

每个场景使用自身 `.ss` 及同目录的全部 `.inc`。Include 文件按文件名 ASCII 小写顺序处理。

源码编码会逐文件检测，也可通过 `--charset` 指定。非法字节默认导致失败，`--allow-invalid` 可启用替换解码。编译会忽略首个 DOS EOF 字符（U+001A）之后的字节及开头的 BOM 字符，并将 CRLF 或孤立 CR 转为 LF，不进行 Unicode 规范化。

### 处理顺序

1. 加载同目录 `.inc` 声明。
2. 删除场景注释、折叠 ASCII 大小写、处理条件指令，并收集 `#inc_start ... #inc_end` 区段。
3. 处理局部声明，展开场景文本中的替换。
4. 检查场景语法、类型和目录级命令定义，再生成 PCK。

场景条件指令先于局部 include 声明处理，因此无法使用这些区段中声明的名称。每个全局 `.inc #command` 必须在目录中恰有一个实现，不能仅以各场景编译通过作为判断依据。

### 字符级处理

#### 大小写折叠

ASCII 关键字、标识符、标签和指令名不区分大小写。字符串、字符字面量及注释外的 `A`–`Z` 会转为小写，非 ASCII 字符保持不变。

#### 注释

SiglusSS语言与 `.inc` 声明文本都接受以下三种注释：

- `;` 到行末；
- `//` 到行末；
- `/* ... */` 块注释。

`/* ... */` 不嵌套。未闭合块注释是错误。注释起始记号在单引号与双引号内部不生效。

场景文件、`.inc` 和 `Gameexe.ini` 的注释分隔符可共用一个 `*`，因此 `/*/` 是闭合的空注释。`/*/text*/` 中的 `text*/` 不在注释内。注释文本请使用 `/* text */`。

#### 条件编译

场景文本与 `.inc` 均支持：

```text
#ifdef <word>
#elseifdef <word>
#else
#endif
```

1. `#ifdef` 和 `#elseifdef` 检查名称是否存在，不检查数值真假。
2. 最多嵌套 15 层，不匹配或未闭合的指令会报错。
3. 待检查名称可用 ASCII 字母、CP932 双字节字符、`_` 或 `@` 开头，后续还可包含数字。
4. 仅最内层条件控制文本保留，不继承外层的假状态。

例如，已存在的 `inner_present` 会使以下 `kept` 保留，不受缺失的 `outer_missing` 影响：

```text
#ifdef outer_missing
#ifdef inner_present
kept
#endif
#endif
```

#### `#inc_start` / `#inc_end`

用 `#inc_start` 和 `#inc_end` 在场景文件内编写局部 `.inc` 声明。区段不可嵌套，不匹配或未闭合时会报错。

#### 源元数据注释

若源码解码后的第一行以这个完全匹配的文本前缀开头：

```text
// #SCENE_SCRIPT_ID = dddd
```

`dddd` 为记录到场景元数据的四位十进制数字，首行后续文本不影响 ID 读取。

### 词法结构

#### 空白与换行

空白包括空格、制表符和换行。换行不结束语句，分号用于行注释。

#### 标识符

场景中的普通标识符遵循：

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

标签以 `#` 开始：

```text
label-token ::= "#" { "_" | ascii-letter | digit }
z-label-token ::= "#z" digit [digit [digit]]
```

- 单独的 `#` 是有效的普通标签。
- Z-label 使用 1–3 位 ASCII 数字。Profile `7` 和 `8` 的数值须小于 `100`，其余须小于 `1000`。
- `#z0`、`#z00` 和 `#z000` 占用同一个数字标签槽，但跳转引用必须与定义的拼写完全一致。`#z1234`，以及 profile `7`/`8` 中的 `#z100`–`#z999`，均为普通标签。
- 标签必须唯一定义，全部引用必须可解析。每个场景都必须定义数值为 `0` 的 Z-label。

#### 整数字面量

支持三类整数字面量：

```text
decimal ::= digit { digit }
binary  ::= "0b" { "0" | "1" }
hex     ::= "0x" { hex-digit }
```

整数为有符号 32 位值，溢出回绕。负号是一元运算符，裸写 `0b` 和 `0x` 均为零。

#### 字符与字符串字面量

单引号字面量与双引号字面量都不得跨物理行。唯一接受的转义写法是：

- `\\`
- `\n`
- 单引号字面量中的 `\'`，或双引号字面量中的 `\"`

双引号中的 `\n` 表示换行，单引号中的 `'\n'` 表示字符 `n`。单引号字面量必须恰好产生一个字符，类型为整数；双引号字面量为字符串。

#### 全角/双字节裸字符串

除 `【` 和 `】` 外，连续的 Windows CP932 双字节字符可直接写为无引号字符串：

```text
"こんにちは"
こんにちは
```

集合以外的非 ASCII 字符需要引号，UTF-8 源码也遵循此规则。角色名可写为 `【名前】`。

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
| 1 | `\|\|` | 左结合 |
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

Profile `7` 将 `&&` 与 `||` 视为相同优先级，按从左到右的顺序结合；其他 profile 均遵循上表。

### `.inc` 声明语言

全局 `.inc` 与场景内嵌 include 区段均支持以下声明：

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

#### 声明名称

- `#replace` / `#define` 名称到空格、制表符或换行结束。
- `#define_s` 名称到制表符或换行结束，可以包含空格。
- `#property` 名称还会在 `:` 处结束，`#command` 名称还会在 `(` 或 `:` 处结束。
- 属性和命令名称可使用普通场景标识符集合以外的字符。
- 宏名必须以 `@` 开头。
- 全部声明共用命名空间，不允许重名。成功声明会立即影响后续 `#ifdef` / `#elseifdef` 判断。

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

`#replace` 插入文本后不立即重新展开插入结果。`#define` 和 `#define_s` 会立即扫描结果并继续替换。

普通定义和宏参数各自选择最长匹配名称。两组均匹配时，字典序较大的候选名称优先，不按声明顺序决定。

#### `#macro`

```text
macro-decl ::= "#macro" macro-name ["(" macro-param {"," macro-param} ")"] replacement-text
macro-name ::= "@" <non-space-sequence>
macro-param ::= param-name ["(" default-text ")"]
```

- 宏按文本替换，实参与默认值会在代入前展开。
- 括号内至少需要一个形参，不接受空的 `()`。
- 实参分割会识别嵌套圆括号和引号字面量。
- 宏体会按形参值展开，插入后的结果不立即重扫。
- 重名形参使用首个同名参数的实参或默认值，后续同名项仍计入形参数量并展开对应值。

**展开限制：** 宏最多嵌套 **128 层**。文本、实参和宏体展开连续超过 **10000 个扫描步骤**未使剩余文本长度降到新低时会停止。Include 的 `#expand` 处理按声明步数采用同一规则，不限制整份文件的宏或声明总数。

超限会导致编译或 LSP 分析失败，请修正循环定义或减少展开深度后重试。

#### `#property`

```text
property-decl ::= "#property" name [":" form-name ["[" integer-literal "]"]]
```

规则：

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

- 默认返回类型为 `int`。
- 形参仅写类型和默认值，不写名称。
- 括号内至少需要一个形参。
- 首个默认参数之后的参数都必须有默认值。
- 可声明 `int` 或 `str` 默认值，但调用时仅可省略整数默认参数，省略字符串默认参数会导致编译失败。

#### `#expand`

```text
expand-decl ::= "#expand" replacement-text
```

`#expand` 会立即展开文本，并将结果作为 `.inc` 声明处理。

### 场景语法

除去内嵌 include 区段后，场景文本语法如下：

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

规则：

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
3. 场景 `property` 和 `command` 形参中的 `form[exp]` 需要 `int` 表达式，但不会像 `.inc #property` 一样为调用局部属性声明固定数组大小。

`command` 返回类型后的方括号表达式会被忽略，返回类型由 `form-name` 决定。

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
- 列表实参外的圆括号不改变其元素数量与类型信息，例如 `wipe(option=([1,2]))` 与 `wipe(option=[1,2])` 等价；
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

元素链 `a.b[c].d(...)` 中可用的后续成员取决于前一段的类型及所选 profile。

#### property 的引用 form

属性表达式使用对应的引用类型：

- `int` -> `intref`
- `str` -> `strref`
- `intlist` -> `intlistref`
- `strlist` -> `strlistref`

赋值左侧必须是引用类型的元素表达式。

#### 未解析名称作为字符串

不带实参且不含 `@`、`$` 的未解析单段名称会作为同名字符串字面量处理。其他未解析元素名会报错。

### 类型与静态约束

#### 分析深度警告

语法嵌套超过 `64` 层或表达式树高度超过 `128` 时会警告，编译和 LSP 分析会继续。警告阈值与[宏展开硬限制](#macro)不同。

#### 一元与二元运算

运算类型：

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

1. Profile `0`–`5`、`9` 和 `10` 仅允许在 `command` 内声明 `property`，profile `6`–`8` 还允许在命令外声明调用局部属性；
2. `if`、`for`、`while` 的条件应为 `int` 或 `intref`；
3. `switch` 条件应为 `int` / `intref` / `str` / `strref`；每个 `case` 值必须与条件同属整数家族或字符串家族；
4. `goto` 表达式 form 为 `void`；`gosub` 为 `int`；`gosubstr` 为 `str`；
5. `continue` 和 `break` 不能用于循环外；
6. 某些 profile 标记为“选择分支相关”的命令，不得出现在条件、普通实参、goto 实参或下标表达式中；这是 profile 相关的额外静态限制；
7. `name-stmt` 产生名字显示事件；`text-stmt` 产生文本显示事件，并消耗一个 read flag 序号。

Profile `0`–`5`、`9` 和 `10` 也不允许在嵌套 `command` 定义之后继续声明局部 `property`，除非位于另一命令定义内。Profile `6`–`8` 允许该用法。

#### command 定义与声明匹配

场景命令可以是局部命令或全局 `.inc #command` 的实现。全局实现的返回类型、参数数量及位置参数类型必须与声明一致，不比较参数名和默认值。

#### 返回值

调用处按声明的返回类型检查。编译器不检查 `return(exp)` 是否符合该类型。

#### 命名实参

只有包含命名参数的命令才接受命名实参。未知名称和类型不匹配会报错。

### 全文件与目录级约束

#### label 与 z-label

每个场景文件必须满足：

1. 普通 label 不得重定义；
2. z-label 不得重定义；
3. 所有被引用的 label 与 z-label 都应存在；
4. `#z0` 必须存在；
5. 所有场景局部 `command` 声明都必须在该文件内得到定义。

#### 全局 `.inc #command` 的目录级链接

每个全局 `.inc #command` 都必须由恰好一个场景实现，包括未使用的声明。缺失或重复实现会导致链接失败。

## 提示与故障排除

### 编译时的意外 token

将含逗号或括号的文本作为单个参数传递时，请加双引号：

```ss
set_namae("Hello, world")
```

### 字符串乘整数的异构乘法

`set_namae("ABC" * 3)` 等字符串乘整数的 `*` 表达式会生成与官方编译器不同的字节码。需要两种编译器生成一致结果时，请先赋值给字符串变量，再使用 `*=`：

```ss
s[0] = "ABC" s[0] *= 3 set_namae(s[0])
```

`s[0] = s[0] * 3` 无法避免该兼容性问题。
