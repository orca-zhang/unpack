# 技术参考

[English](REFERENCE.md) · [中文](REFERENCE_zh.md) · [README](../README_zh.md)

<a id="versions"></a>

## 版本与布局明细

### ASPack 布局版本

以下偏移均相对 PE 入口桩。版本标签表示可识别的布局，不表示该发行版产生的所有程序都能完整脱壳。

| 布局标签 | 兼容 ID | 标记偏移 | 原始入口点字段 | 旧式块表 | 能力 |
| --- | ---: | --- | --- | --- | --- |
| 2.1 | 1 | `0x4fd` | `0x4f4` | 无 | 入口点 / PE 修补；重叠的 RET 字节不作为块计数 |
| 2.12 | 2 | `0x3b9` | `0x748` | `0x57c` | PE 修补 + 有限旧式块布局 |
| OTHER（`0x41f`） | 3 | `0x41f` | `0x7a4` | `0x5d8` | PE 修补 + 有限旧式块布局；厂商版本未知 |
| 2.42 | 4 | `0x42b` | `0x7b0` | `0x5e4` | PE 修补 + 有限旧式块布局 |

依据：[Rust 布局定义](../rust/aspack.rs)、[恢复实现](../rust/recover.rs)、
[合成布局清单](../testdata/pe-versions/manifest.json)。旧式块解码器不是完整原生 ASPack 编解码器。

### UPX 版本、架构与方法

仓库样本使用**官方 UPX 5.1.0**。其他版本的兼容性取决于安装的后端和输入；
当前证据不足以声称完整覆盖 UPX 1.x～5.x。

| 样本 | 可执行文件变体 | 加壳选项 | 实际方法 / 过滤器 | 验证方式 |
| --- | --- | --- | --- | --- |
| `pe32` | PE32 / x86 | `--best` | `2` / `0x16` | 官方解码结果逐字节比较 + SHA-256 |
| `pe32-lzma` | PE32 / x86 | `--lzma` | `14` / `0x16` | 官方解码结果逐字节比较 + SHA-256 |
| `pe32-filter` | PE32 / x86 | `--filter=0x16` | `2` / `0x16` | 官方解码结果逐字节比较 + SHA-256 |
| `pe64` | PE32+ / x86-64 | `--best` | `2` / `0x00` | 官方解码结果逐字节比较 + SHA-256 |
| `elf32` | ELF32 / x86 | `--best` | `2` / `0x00` | 官方解码结果逐字节比较 + SHA-256 |
| `elf64` | ELF64 / x86-64 | `--best` | `2` / `0x00` | 官方解码结果逐字节比较 + SHA-256 |
| `elf-arm64` | ELF64 / ARM64 | `--best` | `2` / `0x00` | 官方解码结果逐字节比较 + SHA-256 |
| `macho64` | 薄 Mach-O 64 / x86-64 | `--best --force-macos` | `2` / `0x49` | 官方解码字节 + 结构；实验性加壳 |

依据：[UPX 样本清单](../testdata/upx/manifest.json)。Mach-O 未验证执行兼容性；ARM64 Mach-O 未列为已验证往返支持。

### 兼容编号不等于厂商版本

识别时先检查节名，再检查字符串。以下映射适用于对应证据胜出的情况；更早命中的证据可能优先。

| 格式 | 识别依据 → 当前 `version` ID | 解读 |
| --- | --- | --- |
| UPX | `UPX0` / `UPX1` / `UPX!` → 1 | 旧 Go 常量 1～4 不代表验证过四个 UPX 发行版 |
| FSG | `FSG!` → 1；`FSG2` → 2 | 签名变体，不是已验证的 1.x / 2.x 发行版范围 |
| WinUpack | `.upx0` / `.upx1` → 1；`WinUpack` → 1；`UPack` → 2 | `WinUpack!` 也会先命中 `WinUpack` |
| PECompact | 节名 → 1；`PECompact` → 1；`PEC2` → 2；`PEC1` → 3 | 按签名顺序编号，不按厂商版本排序 |
| MPRESS | `.MPRESS1` / `.MPRESS2` → 1；`MPRESS` 字符串 → 1 | 节名中的 1 / 2 不能用来区分产品发行版 |

### 可执行文件容器变体

| 容器 | 结构处理范围 | 真实 UPX 往返样本 |
| --- | --- | --- |
| PE | PE32（`0x10b`）、PE32+（`0x20b`） | x86 / x86-64 |
| ELF | ELF32 / ELF64，大端 / 小端头部校验 | 小端 x86 / x86-64 / ARM64 |
| Mach-O | 薄文件 32 / 64 位、通用 FAT32 / FAT64、两种字节序 | 仅薄文件 x86-64 |

结构校验覆盖范围大于真实加壳样本范围，不能据此推断所有 CPU、容器版本或商业保护壳都能解包。

## 识别与恢复说明

静态恢复会尝试还原入口点、修补部分 PE 字段，不等于通用解压、去虚拟化或保证程序可运行。
旧 ASPack 样例只验证 PE 结构和入口点，没有执行成功的证明。Rust API 和 CLI 默认关闭
静态恢复，需显式启用；原 Go 解包方法为兼容保留恢复行为，并在聚合结果的 `Warnings`
中说明。单驱动 `Unpack` 的返回类型不支持提示，应结合 `Inspect` 的能力字段判断。

识别使用节名和格式签名，并采用稳定顺序；不再只凭 `PUSHAD; CALL` 等通用指令判定壳。
`.vmp*` 归为 VMProtect。重命名节、修改桩代码等仍可能影响识别。
`version` 是兼容旧 Go 常量的编号，不表示厂商的实际版本。

<a id="build-and-install"></a>

## 安装与构建

需要 Rust 1.85+；使用 Go SDK 时需要 Go 1.21.5+。UPX 解包还需要安装
[官方 UPX](https://upx.github.io/)，样例使用 5.1.0 生成。识别、AP32 解码和静态恢复不依赖 UPX。
GZIP、ZLIB、XZ、LZMA 载荷解码也不需要外部解压程序。工具不会执行待分析的程序。

```sh
cargo build --release --locked
# 或将 Rust 程序安装到 PATH：
cargo install --path . --locked
```

Go SDK 通过 cgo 静态链接 Rust 核心。构建时需要 Rust、Python 3 和 C 编译器，部署时无需
Rust CLI 或 Rust 动态库。`UNPACK_UPX` 可指定官方 UPX 程序路径。

<a id="cli"></a>

## 命令行

```sh
unpack detect --json testdata/upx/pe32.packed
unpack unpack -o output.exe testdata/upx/pe32.packed
unpack unpack -o decoded.exe testdata/aplib/upx.ap32
unpack unpack -o decoded.exe testdata/payloads/gzip-xz-upx.packed
unpack unpack --format LZMA -o payload.bin testdata/payloads/text-lzma.packed
unpack unpack --depth 5 --max-size 268435456 input.exe
unpack unpack --recover -o recovered.exe testdata/aspack/aspack_test.exe
unpack formats
```

默认输出为 `<文件名>_unpacked.<扩展名>`。默认保留已有文件，只有 `--force` 才会替换输出，
即使指定 `--force` 也不能覆盖输入。输出完成后再发布到目标路径。

默认最多 10 层，单层输入/输出最大 256 MiB，每次 UPX 调用最多 30 秒。
`--depth 0` 取消配置的层数限制，仍有 1024 层硬限制和循环检查。
内置多层处理在内存中传递数据，官方 UPX 调用使用临时目录并在正常结束或报错时清理。
输出大小限制不等于对 UPX 进程本身内存的限制。
XZ/LZMA 的字典与模型另有固定 64 MiB 内存上限。LZMA-Alone 没有可靠魔数，默认不猜测识别。
指定格式时只处理一层；自动模式会继续校验已识别的内层可执行文件或容器。
需要外部预置字典的 ZLIB 流会返回不支持。LZMA-Alone 本身没有校验和，工具会检查严格结束条件和声明长度。

Mach-O 样本生成使用上游 UPX 的实验选项 `--force-macos`；测试验证解包字节和结构，
不证明加壳程序在 macOS 上可运行。ARM64 Mach-O 暂不列为已验证往返支持。

## Go SDK

内置驱动保留原调用方式。

先在可写的仓库副本中构建静态库，再编译 Go：

```sh
python3 scripts/build_go_sdk.py  # 或 go generate .
go build ./examples/go
```

在其他 Go 项目中，使用已生成静态库的仓库副本：

```sh
go mod edit -replace github.com/orca-zhang/unpack=/absolute/path/to/unpack
```

构建目标包括 macOS amd64/arm64、Linux GNU amd64/arm64、Windows amd64。
Windows 使用 MinGW GCC 和 `x86_64-pc-windows-gnu` Rust 目标。脚本读取 `GOOS`/`GOARCH`；
交叉编译还需安装相应 Rust target 和 C 交叉编译器，并启用 `CGO_ENABLED=1`。
静态库由脚本生成且不提交 Git，单独 `go get` 不足以完成构建。Rust 修改后需重建静态库；
脚本会清理 Go 编译缓存，确保链接新库。Go 命令行与自定义 Go 解包实现已移除。

```go
package main

import (
    "fmt"
    "github.com/orca-zhang/unpack"
    _ "github.com/orca-zhang/unpack/drivers"
)

func main() {
    result, err := unpack.UnpackAll("packed.exe")
    if err != nil { panic(err) }
    for _, layer := range result.History {
        fmt.Println(layer.PackerName, layer.Version, layer.Support)
    }
    for _, warning := range result.Warnings { fmt.Println(warning) }
    // result.ReaderAt 为内存结果，不需要 Close。
}
```

导入 `drivers` 注册全部 22 种格式，也可以只导入 `_ "github.com/orca-zhang/unpack/drivers/upx"`，
或导入 `github.com/orca-zhang/unpack/drivers/ap32` 单独注册原生 AP32 解码。
各格式驱动现统一放在 `drivers/` 下，旧导入路径需在格式名前加上 `/drivers`。
SDK 主包及聚合 `drivers` 的导入路径保持不变。
`DetectFormat` 仅检查已注册格式，保留出错时返回未识别的旧签名。
新增 `Inspect(path)` 能返回错误、识别依据和能力字段，不受驱动注册范围限制。
`RegisterFormat` 只选择实现 `RustFormat()` 的 Rust SDK 适配器；旧 Go 检测/解包回调会返回 `unsupported`，不会执行。

需要上下文取消、明确限制和严格模式时：

```go
result, err := unpack.UnpackWithOptions(ctx, path, unpack.Options{
    MaxDepth: 10,
    MaxSize: 256 * 1024 * 1024,
    AllowRecovery: false,
})
```

Rust 业务错误为 `*unpack.Error`，错误码包括 `invalid_input`、`unsupported`、`limit`、
`backend`、`io`、`cancelled`、`internal`。C ABI 持有元数据和结果，Go 复制结果一次后释放 Rust
内存，Rust panic 在 ABI 边界捕获。SDK 不再查找 CLI、启动 Rust 子进程或通过 base64 传输。
CLI 仍保留 RPC 协议 1/2，供其他现有客户端使用。
Go 请求有两分钟超时；取消上下文会及时返回，并通知 Rust 终止、回收 UPX 进程。
原生编解码器在层边界检查取消，已开始的单层解码可能在 Go 返回后继续完成。

无需注册驱动即可显式解码一层 LZMA-Alone：

```go
result, err := unpack.UnpackWithOptions(ctx, path, unpack.Options{Format: "LZMA"})
```

也可分别导入 `gzip`、`zlib`、`xz`、`lzma` 包，使用与原驱动相同的接口。

## Rust 库

```rust
use unpack::{Options, unpack_path};

fn main() -> unpack::Result<()> {
    let result = unpack_path("packed.exe", &Options::default())?;
    for layer in result.history { println!("{}", layer.packer_name); }
    Ok(())
}
```

也可使用 `detect(&[u8])`、`detect_format`、`unpack(&[u8], &Options)`、`unpack_format`。
指定单个格式时只处理一层，对应原 Go 单驱动接口。
静态恢复后可能仍保留壳节名，因此恢复后停止继续识别，避免把相同标记当成新的壳层。

新增 `unpack_owned(Vec<u8>, &Options)`、`unpack_format_owned`，直接消费已有缓冲区，
避免初始整文件复制，CLI 和 `unpack_path` 已采用此路径。
`aplib::decompress(raw, max_size)` 可解码原始 aPLib 数据；自动识别只接受有明确头部的 AP32。
AP32 会校验声明长度、压缩数据 CRC 和输出 CRC，非法回溯、缺失结束标记、超限输出会报错。
支持 AP32 不等于已经完整实现内部使用 aPLib 的各种 PE 壳。
`compression::unpack(data, format, max_size)` 可直接解码单个 GZIP/ZLIB/XZ/LZMA 载荷。
Mach-O 校验覆盖薄文件、通用容器、32/64 位及大小端；真实 UPX 往返样本目前覆盖 x86-64 薄文件。

可直接运行 SDK 示例：

```sh
cargo run --example basic -- testdata/upx/pe32.packed
go run ./examples/go testdata/upx/elf64.packed
```

## 验证与样例

```sh
cargo build --locked
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
python3 scripts/build_go_sdk.py
go test -race ./...
go vet ./...
```

仓库包含由无害 C 源码生成的真实 UPX PE32、PE64、ELF64、LZMA、x86 filter 样本，
保存官方解包结果和 SHA-256 清单；测试逐字节比较，不只检查长度或入口点变化。
UPX 样本已增至 8 个变体，新增 ELF32、ARM64 ELF、x86-64 Mach-O。
另有 20 个独立载荷案例，覆盖空流、多成员、XZ BCJ/delta/SHA-256、已知长度 LZMA，
以及 GZIP → XZ → UPX 等真实数据链。
新增 5 组经独立解码器核对的 AP32/raw aPLib 向量，覆盖各类编码、偏移边界、嵌套容器，
以及真实的 AP32 → UPX 数据链。
合成 PE 桩覆盖全部格式识别、旧驱动静态恢复、畸形输入、资源限制、Go 注册机制、
静态库调用、上下文取消，以及拒绝执行旧 Go 回调。合成样例不能证明真实商业壳能够完整脱壳。
测试不再因为这些样本缺失而跳过。来源与重建方法见 [testdata/README.md](../testdata/README.md)。

版本矩阵增加 **105 个合成用例**，其中 ASPack 四种布局共 **81 例**，覆盖入口偏移、节顺序、
导入表、截断/歧义标记、文件映射边界和旧块流。另有 **16 个真实 RetDec 样本**：
ASPack 2.12、FSG 1.33、MPRESS 1.05/1.27/2.05/2.19，覆盖代码/数据排列与 LZMA/LZMAT 差异。
真实样本要求正确识别并拒绝无法验证的恢复；上游原始文件用于证明跳到压缩节不是原始入口。
ASPack 2.42/OTHER 目前只有合成布局覆盖。来源提交、许可和哈希见样本清单。

CI 配置覆盖 Linux、macOS、Windows 的静态库链接与测试。`CGO_ENABLED=0` 可编译错误占位实现，
实际 SDK 操作需要 cgo 和 Rust 静态库。

## 重建图表

构建 release CLI 后，用 `python3 scripts/generate_demo.py` 重建终端演示。
需要 Pillow、官方 UPX，以及 `shasum` 或 `sha256sum`。
脚本采集真实输出，并逐字节核对解包结果；播放节奏为便于阅读作了调整。

7 张图表均提供中英文版本，采用统一的矢量样式，依据仓库测量数据、样本大小和实时格式元数据生成。
[实现与性能报告](REPORT.md) 包含识别、CRC/AP32、SDK 分配和样本大小的详细图表。

```sh
make benchmark  # 重测当前实现，保留历史基线
make charts     # 根据测量数据和实际格式列表重建 SVG
python3 scripts/generate_charts.py --check
```

CI 只检查图表与数据是否一致，不重复运行依赖机器性能的基准。
[Logo](assets/logo.svg) 和[头图](assets/hero.svg) 均为独立、可编辑的 SVG；
图表生成只使用 Python 标准库。
