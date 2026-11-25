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

Go SDK 运行时依次寻找 `UNPACK_RUST_BIN`、PATH 中的 `unpack-rs`、当前源码目录下
`target/release` 或 `target/debug` 的程序；两个构建同时存在时选择较新的程序，避免使用过期版本。不会自动编译或下载。
可通过 `UNPACK_UPX` 指定官方 UPX 的路径。这两个变量均为可执行文件路径，不是 shell 命令。
无需 cgo，也没有新增 Go 模块依赖。部署时需一并提供 Rust 程序，单独 `go get` 已不足以
获得完整运行环境。

<a id="cli"></a>

## 命令行

```sh
unpack-rs detect --json testdata/upx/pe32.packed
unpack-rs unpack -o output.exe testdata/upx/pe32.packed
unpack-rs unpack -o decoded.exe testdata/aplib/upx.ap32
unpack-rs unpack -o decoded.exe testdata/payloads/gzip-xz-upx.packed
unpack-rs unpack --format LZMA -o payload.bin testdata/payloads/text-lzma.packed
unpack-rs unpack --depth 5 --max-size 268435456 input.exe
unpack-rs unpack --recover -o recovered.exe aspack/testdata/aspack_test.exe
unpack-rs formats
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

原来的调用方式仍然可编译：

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

导入 `drivers` 注册全部 22 种格式，也可以只导入 `_ "github.com/orca-zhang/unpack/upx"`，
或导入 `github.com/orca-zhang/unpack/ap32` 单独注册原生 AP32 解码。
`DetectFormat` 仅检查已注册格式，保留出错时返回未识别的旧签名。
新增 `Inspect(path)` 能返回错误、识别依据和能力字段，不受驱动注册范围限制。
自定义 Go 驱动优先于内置驱动，并按注册名称排序。

需要上下文取消、明确限制和严格模式时：

```go
result, err := unpack.UnpackWithOptions(ctx, path, unpack.Options{
    MaxDepth: 10,
    MaxSize: 256 * 1024 * 1024,
    AllowRecovery: false,
})
```

Rust 业务错误为 `*unpack.Error`，错误码包括 `invalid_input`、`unsupported`、`limit`、
`backend`、`io`。引擎不存在或协议故障返回普通 Go 错误。
内置多层操作只启动一次 Rust 进程，通过协议 2 的“JSON 元数据行 + 原始二进制”传递结果。
Go 直接复用接收缓冲区，省去 base64 编解码及其数据分配。Rust 仍支持旧协议 1，供旧客户端使用；
当前 Go SDK 需配套支持协议 2 的 Rust 引擎。Go 请求还有两分钟超时，进程启动和管道 I/O
仍有成本，这不是进程内绑定。
自定义 Go 插件复用一个私有临时文件衔接层级；混合路径复用识别元数据、传播引擎错误，
并将上下文与大小限制传给内置解码器。插件自身的运行时间与资源仍由插件负责。

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
自定义插件和混合多层处理。合成样例不能证明真实商业壳能够完整脱壳。
测试不再因为这些样本缺失而跳过。来源与重建方法见 [testdata/README.md](../testdata/README.md)。

CI 配置覆盖 Linux、macOS、Windows，Go SDK 保留 `CGO_ENABLED=0` 构建能力。

## 重建图表

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
