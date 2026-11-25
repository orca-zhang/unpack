<p><img src="assets/logo.svg" width="64" height="64" alt="Unpack Logo"/></p>

# 实现与性能图表

[项目首页](../README_zh.md) · [完整格式与版本表](../README_zh.md#formats) · [English](../README.md)

当前实现新增 GZIP、ZLIB、XZ、LZMA-Alone 载荷解码，扩展 UPX 的 ELF32、ARM64 ELF、
x86-64 Mach-O 样本，并优化 AP32 校验和与 Go 插件处理。
图表来自实际格式表、样本文件和本机测量，原始数据保存在本目录。
性能对比的柱长采用对数缩放，数值与倍率保留实测值；格式分布和样本大小仍按比例绘制。

![关键指标总览](charts/overview-zh.svg)

| 图表 | 读图重点 | 数据来源 |
| --- | --- | --- |
| [功能流程](charts/workflow-zh.svg) | 原生解码、外部 UPX、静态恢复、仅识别的区别 | [实际格式列表](formats.json)与 Rust 处理路径 |
| [支持分布](charts/support-zh.svg) | 6 条解码路径、10 种恢复、6 种仅识别 | [formats.json](formats.json) |
| [样本大小](charts/upx-fixtures-zh.svg) | 8 个真实 UPX 变体；不作为通用压缩率结论 | [UPX 清单](../testdata/upx/manifest.json)与样本文件 |
| [AP32 / CRC 耗时](charts/ap32-decode-zh.svg) | 对数柱长，标注为真实数值，越低越好 | [优化前](benchmarks/codecs-before.json) / [优化后](benchmarks/codecs-after.json) |
| [识别耗时](charts/native-detection-zh.svg) | 同时展示未命中路径改善和短路径的轻微回退 | [基线](benchmarks/baseline.json) / [优化后](benchmarks/optimized.json) |
| [SDK 分配量](charts/sdk-allocations-zh.svg) | 仅响应解码阶段分配，不是 SDK 总内存 | [rpc.txt](benchmarks/rpc.txt) |

## 实际能力

![功能与处理路径](charts/workflow-zh.svg)

![格式支持范围](charts/support-zh.svg)

22 种内置格式中，AP32、GZIP、ZLIB、XZ、LZMA-Alone 由 Rust 原生解码，UPX 使用官方外部程序。
10 种旧壳仅做有限静态 PE 恢复，另有 6 种只识别。载荷编解码能力与完整 PE 壳恢复是不同的能力：
新增 LZMA 或 aPLib 解码，不等于已经完整实现所有使用这些算法的保护壳。

ASPack 按 2.1、2.12、2.42、OTHER（`0x41f`）四种布局区分恢复字段。
FSG、WinUpack、PECompact 的 `version` 是兼容签名编号，MPRESS 的节名后缀也不是厂商版本。
详细布局偏移、UPX 5.1.0 的 8 个变体，以及 PE / ELF / Mach-O 结构范围见[版本明细](REFERENCE_zh.md#versions)。

LZMA-Alone 没有可靠魔数，需 `--format LZMA`、Go `Options{Format: "LZMA"}` 或命名驱动；
显式选择只处理一层。XZ/LZMA 字典与模型有独立的 64 MiB 内存上限，输出还受 `max_size` 限制。
GZIP、ZLIB、XZ 校验其格式中的完整性字段；LZMA-Alone 本身没有校验和，检查声明长度与严格结束状态。
需要外部预置字典的 ZLIB 暂不支持。

```mermaid
sequenceDiagram
    participant App as Go 应用
    participant SDK as Go SDK
    participant CLI as Rust CLI
    participant Core as Rust 核心
    participant UPX as 官方 UPX
    App->>SDK: UnpackAll(gzip-xz-upx.packed)
    SDK->>CLI: 协议 2 JSON 请求
    CLI->>Core: 移交输入 Vec
    Core->>Core: 原生 GZIP 解码与校验
    Core->>Core: 原生 XZ 解码与校验
    Core->>UPX: 私有临时文件中的 UPX 数据
    UPX-->>Core: 解包后的 PE
    Core-->>CLI: 数据与三层历史
    CLI-->>SDK: JSON 头 + 换行 + 原始二进制
    SDK-->>App: ReaderAt 与层级历史
```

内置流程在内存中传递数据；Go 自定义插件路径改为复用一个私有临时文件，避免每层保留一份磁盘数据。
混合插件路径复用检测结果，去掉重复查询，向内置解码器传递上下文和大小限制，并传播引擎错误。
本地 debug/release 同时存在时选择较新的构建，避免旧程序遮蔽当前实现。

## 样本与实际覆盖

![UPX 样本大小](charts/upx-fixtures-zh.svg)

8 个 UPX 变体来自无害的 `testdata/src/tiny.c`，覆盖 PE32/64、ELF32/x86-64/ARM64、
x86-64 Mach-O、LZMA 方法与 x86 filter `0x16`。生成器检查 UPX 实际选择的方法/过滤器，
并保留官方解码结果。UPX 可能规范化文件头，完整文件未必与加壳前字节相同。

Mach-O 生成使用上游实验选项 `--force-macos`，只验证解包字节和结构，不证明加壳程序能在 macOS 运行。
ARM64 Mach-O 候选被上游解码器拒绝，因此未列为已验证往返支持。通用 Mach-O、大小端及 32/64 位
结构由合成测试覆盖，不作为真实通用程序脱壳的证明。

另有 5 组经独立解码器核对的 AP32/raw aPLib 向量，以及 20 个 Python 标准编解码器生成并往返校验的
载荷案例，包含空流、多成员、多流、XZ BCJ/delta/SHA-256、已知长度 LZMA、容器到 UPX 的真实数据链。
测试会拒绝畸形输入、截断、尾随数据、错误校验和、非法字典大小和过量输出。所有测试只解码，不运行样本。

样本较小且数据重复度高，压缩比不能外推到真实软件。AP32 测试编码器主要发出 literal，
不参与压缩比比较。来源与重建方法见 [样本说明](../testdata/README.md)。

## AP32 解码优化

![AP32 校验与解码耗时](charts/ap32-decode-zh.svg)

用 `crc32fast` 替代逐位循环，校验多项式与结果不变。以下数据来自 Apple M4 Pro、release 构建，
同一 65 KiB 输入重复 5 批，每批 200 次；先计算每批平均耗时再取中位数。

| 路径 | 优化前 | 优化后 | 本机微基准比值 |
| --- | ---: | ---: | ---: |
| CRC32 校验 | 393.21 μs | 0.95 μs | 约 412.7 倍 |
| AP32：两个 CRC + 解码 | 872.39 μs | 50.43 μs | 约 17.3 倍 |

原始记录：[codecs-before.json](benchmarks/codecs-before.json)、[codecs-after.json](benchmarks/codecs-after.json)。
计时包含相应函数内的校验、分配与解码，不包含文件读取、管道、进程启动和其他格式。
热缓存固定样本的结果不是全库、所有输入或端到端加速保证。

## 检测优化

![原生识别耗时](charts/native-detection-zh.svg)

每个结果取 5 批、每批 1,000 次的平均耗时中位数，计时不包含编译和读取文件。

| 路径 | 历史基线 | 当前记录 | 说明 |
| --- | ---: | ---: | --- |
| 普通 PE，所有壳签名均未命中 | 4.32 ms | 51.00 μs | 快速字符串搜索减少无匹配扫描开销 |
| UPX PE，节名直接命中 | 159.54 ns | 168.75 ns | 短路径的绝对差异很小，新增格式判断带来少量开销 |

原始数据：[baseline.json](benchmarks/baseline.json)、[optimized.json](benchmarks/optimized.json)。
机器、命令和输入哈希见 [environment.json](benchmarks/environment.json)。历史基线是在替换签名搜索前
采集的快照，普通重测不覆盖它，不应拿另一台机器的当前测量直接比较。柱长使用对数缩放，数值与比值仍按原始测量值计算。

## Go SDK 结果传输

![SDK 解码分配](charts/sdk-allocations-zh.svg)

协议 1 将结果编码成 base64；协议 2 只解析 JSON 元数据行，复用接收到的二进制数据作为 `ReaderAt`。
Rust 仍接受协议 1，当前 Go SDK 需配套支持协议 2 的 Rust 引擎。

| Payload | base64 解码分配 | 二进制帧解码分配 |
| --- | ---: | ---: |
| 64 KiB | 74,056 B/op | 336 B/op |
| 4 MiB | 约 4.01 MiB/op | 336 B/op |

这只测量“已有响应缓冲区 → 解码结果”，不含接收缓冲区本身、启动、管道和 Rust 解包，
因此 336 B/op 不是 SDK 总内存，解码时间也不是完整 payload 的 I/O 吞吐量。
原始记录见 [rpc.txt](benchmarks/rpc.txt)，每例重复 5 次。

Rust 的 `unpack_owned` / `unpack_format_owned` 去掉初始整文件复制；文件读取按已知大小预留容量。
未加壳输入的测试通过指针比较证明直接沿用原有 allocation。Go 混合原生/自定义路径也直接使用
内置解码器返回的缓冲区，避免再复制一次结果。

## 重建和验证

```sh
python3 scripts/benchmark.py
cargo build --release --locked
python3 scripts/generate_charts.py --engine target/release/unpack-rs
python3 scripts/generate_charts.py --check --engine target/release/unpack-rs
```

图表生成只用 Python 标准库。`formats.json` 由实际 Rust 程序导出，CI 检查格式列表和图表是否过期；
CI 不重跑机器相关的性能基准。SVG 包含标题、描述和数值，可以独立打开或嵌入文档。
