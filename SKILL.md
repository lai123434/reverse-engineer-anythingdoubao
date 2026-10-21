---
name: reverse-engineer-anything
description: 用户需要逆向分析 exe / dll / apk / asar / 固件等二进制文件，反编译函数、搜索字符串、分析 PE/ELF 结构、查看 .NET 元数据、比较版本差异时使用。基于 REA CLI + Ghidra 驱动原生反编译。普通源码仓库架构分析不需要本技能。
---

# REA (Reverse Engineer Anything) — 豆包原生 CLI 版

本 skill 通过 `npx -y rea-agents@6.7.0` 命令行驱动逆向工程分析，
不依赖 MCP server 注册，直接在豆包 PowerShell 环境中运行。

## 已验证命令（实测可用）

| 命令 | 用途 | Windows 可用 |
|------|------|-------------|
| `inspect-artifact` | 通用工件清单 | ✅ |
| `inspect-managed-artifact` | .NET 元数据检查 | ✅ |
| `inspect-go-binary` | Go 二进制元数据 | ✅ |
| `inspect-electron-fuses` | Electron 熔断配置 | ✅ |
| `search --kind strings --provider ghidra` | Ghidra 字符串搜索 | ✅ |
| `search --kind procedures --provider ghidra` | Ghidra 函数搜索 | ✅ |
| `decompile --provider ghidra` | Ghidra 伪代码反编译 | ✅ |
| `trace --provider ghidra` | Ghidra 特性追踪 | ✅ |
| `xrefs --provider ghidra` | Ghidra 交叉引用 | ✅ |
| `inspect-electron-fuses` | Electron 熔断配置 | ✅ |
| `inspect-analysis-view` | 证据摘要视图（inline 模式） | ✅ |
| `doctor` / `providers` | 环境诊断 | ✅ |
| `analyze-javascript-application` | JS/Electron 静态分析 | ✅ |
| `inspect-binary-layout` | 二进制布局（ELF only） | ❌ |
| `inspect-evm-interface` | EVM 字节码分析 | ❌ |

## 快速导航

- [命令模式说明](#命令模式说明重要) — 两种命令模式的区别（先看这个）
- [三分钟快速上手](#三分钟快速上手) — 拿到 exe 先跑这 5 步
- [EXE 模块化拆分粗筛](#exe-模块化拆分粗筛第一层本地脚本) — Ghidra 前先列模块清单、按需深挖（零依赖本地脚本）
- [命令速查表](#命令速查表按功能分组) — 按功能分类的命令索引
- [路由决策](#路由决策先判断目标类型) — 根据目标类型选命令
- [Ghidra Native 分析](#native-pe--elf--mach-o) — 原生反编译详细
- [JS/Electron 分析](#javascript--electron--asar) — Web 应用分析
- [证据复用](#证据复用与深入查看) — 复用已有证据，不重复分析
- [加速技巧](#加速技巧用-snapshot-避免重复分析) — 用 snapshot 提速 30 倍
- [输出解读指南](#输出解读指南) — 大 JSON 怎么读
- [实战案例](#实战案例逆向-notepadexe) — notepad.exe 完整逆向流程
- [故障排查](#故障排查) — 常见报错和解决方法

> 💡 **完整命令清单**：跑 `npx -y rea-agents@6.7.0 --llms` 可以获取全部 153 个命令的 LLM 友好表格。

## 常见场景速查

| 我想... | 第一步跑什么 |
|---------|-------------|
| 分析一个陌生的 .exe / .dll | `inspect-artifact <path>` |
| 先快速看 exe 有哪些功能模块、有无高危行为（不启动 Ghidra） | `python tools\pe_module_scan.py <path> --report r.md` |
| 看看这个 exe 是不是 C# 写的 | `inspect-managed-artifact <path>` |
| 搜 exe 里的某个字符串（公司名/API名） | `search <path> "关键词" --kind strings --provider ghidra` |
| 反编译某个函数看伪代码 | `decompile <path> <地址> --provider ghidra` |
| 分析一个 Electron 应用 | `analyze-javascript-application <path>` |
| 分析一个 Android APK | `inspect-android-package <apk>` |
| 看看这个文件是什么格式 | `inspect-artifact <path>` |
| 诊断环境有什么问题 | `doctor` |

---

## 命令模式说明（重要）

REA CLI 有两种命令模式，别搞混了：

| 模式 | 特点 | 示例 |
|------|------|------|
| **直接分析模式** | 传入文件路径，直接分析 | `inspect-artifact <path>`、`search <path> "关键词"` |
| **证据二次分析模式** | 传入 inputJson 文件，基于已有证据做分析 | `inspect-analysis-view <request.json>`、`compare-application-versions <request.json>` |

**证据二次分析模式**的命令需要先构造一个 JSON 请求文件，里面包含证据对象和参数。用 PowerShell 组装，注意 UTF-8 无 BOM。

## 快速启动

首次使用前，确认 Node.js 环境可用：

```powershell
node --version   # 需要 18+
npx --version
```

所有 REA 命令统一格式：

```powershell
npx -y rea-agents@6.7.0 <command> <参数> --format json
```

**输出处理规范**：大 JSON 必须重定向到文件，再用 Read 工具分段读取：

```powershell
npx -y rea-agents@6.7.0 inspect-artifact "C:\path\to\app.exe" --format json > "$env:TEMP\rea-output.json"
```

## 三分钟快速上手

拿到一个陌生的 .exe，按这个流程走：

```powershell
# 第 1 步：基础信息（格式、大小、哈希）
npx -y rea-agents@6.7.0 inspect-artifact "C:\path\to\app.exe" --format json

# 第 2 步：是不是 .NET 写的
npx -y rea-agents@6.7.0 inspect-managed-artifact "C:\path\to\app.exe" --format json

# 第 3 步：搜关键字符串（比如公司名、API 名）
npx -y rea-agents@6.7.0 search "C:\path\to\app.exe" "CreateFile" --kind strings --provider ghidra --format json

# 第 4 步：搜函数名（注意：无 PDB 的 PE 里用户函数都是 FUN_xxxxxx，搜 WinMain 只能找到 CRT 外部函数）
npx -y rea-agents@6.7.0 search "C:\path\to\app.exe" "WinMain" --kind procedures --provider ghidra --format json

# 第 5 步：反编译某个函数看伪代码（用上一步搜到的地址）
npx -y rea-agents@6.7.0 decompile "C:\path\to\app.exe" 0x140002910 --provider ghidra --format json
```

## EXE 模块化拆分粗筛（第一层，本地脚本）

> 解决"信息过载"：不要一上来就让 Ghidra 吐出全部反编译结果。先用零依赖本地脚本
> 把 EXE 内部能力粗分成功能模块，**先给清单、由用户选模块，再对单个模块深挖**。

### 定位

- 位置：`tools/pe_module_scan.py`，**纯 Python 标准库，无需 pip 装包**，可直接 PyInstaller 打包单 EXE。
- 原理：解析 PE **导入表**（DLL + API）+ 提取 ASCII/UTF-16 **字符串**，按规则归类，**不启动 Ghidra、不运行目标**，秒级出结果。
- 与 Ghidra 的关系：本脚本是第一层粗筛；选定模块后，再用 Ghidra `trace`/`decompile`/`xrefs` 对该模块 API 做调用链深挖。

### 用法

```powershell
# 基础：终端打印模块清单 + 风险评分
python tools\pe_module_scan.py "C:\path\to\app.exe"

# 完整：同时生成中文 Markdown 报告和结构化 JSON
python tools\pe_module_scan.py "C:\path\to\app.exe" `
  --report report.md --json result.json

# 只看高置信模块（high/medium/low，默认 low 全显），隐藏弱字符串噪声
python tools\pe_module_scan.py "C:\path\to\app.exe" --min-confidence high

# 批量分诊：递归扫描目录 exe/dll，按风险分降序排名，--report 落盘总表
python tools\pe_module_scan.py --batch "C:\downloads" --report rank.md

# 基线巡检：--baseline 存哈希+分数，复扫标注 新增/已替换/风险上升/已见
python tools\pe_module_scan.py --batch "C:\downloads" --baseline db.json
```

### 输出怎么读

- **风险评分 0-100 / 等级**：安全低关注(<20) / 低危需关注(20-39) / 可疑需复核(40-69) / 高危(≥70)。
  高危项（进程注入、键盘记录、提权、录音、截屏、下载执行、文件加密、服务持久化等）计入评分；
  `IsDebuggerPresent`、`OpenProcessToken`、`OpenClipboard` 等运行库常见项**只提示不计分**。
  **已签名样本**（多为合法系统/厂商程序）原始分按 0.35 减免，避免系统库普遍导出高危 API 造成满分误报。
- **样本信息**：EXE/DLL、GUI/控制台子系统、编译时间戳、架构、SHA-256、数字签名有无、节区数、**类型/运行时**（.NET 托管 / Go /
  Electron/NW.js / CEF / Node / Python 打包 / UPX 加壳 / 原生 C/C++）、
  加壳/可疑提示：**高熵节区**（熵≥7.0）、**节区名识别加壳器**（UPX/VMProtect/Themida/ASPack）、
  **入口点不落节区**、**RWX 可写可执行节区**；报告附节区明细表（熵 + X/R/W 权限，高熵/RWX 标⚠️）；
  类型识别会给出换用对应工具链的提示。
- **外联证据**：自动提取硬编码 URL / IPv4 / 域名；公网 IP/域名列出并建议核查归属/信誉，
  回环/内网（10/192.168/172.16-31/169.254）归入 `private_ips` 参考、不计可疑；过滤微软帮助链接、
  占位域名（example.com）、版本号和源文件名噪声；JSON 顶层 `network_evidence` 供程序消费。
- **非 PE 引导**：识别 ELF/Mach-O/Java class/ZIP 魔数，给出对应原版 `inspect-*` 命令，不笼统报错。
- **批量与基线**：`--batch` 目录分诊排名并可落盘 Markdown；`--baseline` 指纹库复扫对比新增/替换/风险上升/已见。
- **组合联动判断**：命中“注入+外联”“注入+持久化”“凭据+外联”等高危组合时，小结给出特征链提示（仅提示，不改阈值）。
- **模块清单**：每个模块带置信度（高=≥2 精确 API；中=1 精确 API；低=仅弱字符串），
  列出命中的精确 API 与字符串证据，并附一条对应的 Ghidra/REA 深挖命令。
- **模块分类**：网络通信 / 图形界面 / 加密编码 / 文件读写 / 进程管理 / 注册表读写 /
  服务管理 / 动态加载延迟绑定 / 自启动持久化 / 进程注入(高危) / 反调试 / 提权令牌 /
  录音采集 / 屏幕截取 / 剪贴板 / 键盘记录(高危) / 下载执行 / 文件加密 /
  凭据窃取·反取证(高危) / 反虚拟机·反沙盒 / 数据外泄(FTP/邮件) / 破坏安全软件 /
  勒索特征(高危)。

### 打包单 EXE

```powershell
# 在 tools 目录执行，产物 dist\pe_module_scan.exe（需先 pip install pyinstaller）
tools\build_exe.bat
```

### 退出码（供流水线/CI 判定）

- `0` 安全 / 低关注 / 低危；`1` 可疑需人工复核；`2` 高危；`3` 非有效 PE；`1` 也用于文件不存在/读取失败。
- `--min-confidence high|medium|low` 过滤低置信噪声模块（默认 low 全显）；纯字符串高危模块（勒索/反沙盒）命中字符串时始终保留。
- `--quiet` 精简为只打印风险结论，供流水线；`--version` 打印版本。
- 回归测试：`python tools\test_scan.py`（110 项断言，改动后必跑；含计分API→模块归类对账守护）。
- 解析层对截断/损坏 PE 做边界防护：thunk 宽度、数据目录、optional header 越界均返回 None，不抛 struct/IndexError；失败扫描与缺哈希条目不污染基线库。

### 粗筛后如何深挖（衔接 Ghidra）

1. 从模块清单挑用户关心的模块，记下命中的代表 API。
2. 用 `search --kind strings` / `trace` 定位该 API，再 `xrefs` 找调用处、`decompile` 看伪代码。
3. **纪律**：粗筛结论是"具备该能力"的**静态推断**，不等于运行时真的使用；
   最终报告须区分【观察 / 推断 / 未知】，命中高危 API 也要结合反编译确认后再下恶意结论。

### 边界

- 仅支持 Windows PE（exe/dll）；ELF/Mach-O/APK 走对应 REA 命令。
- 粗筛靠导入表 + 字符串，静态链接进自身、无导入表的能力识别不到，精度有限。

### 已知限制与后续路线（本地零依赖层之后）

- **已放弃（易错、增益低）**：VS_VERSION_INFO 厂商/产品名启发式提取、PE 导出表解析——
  纯手工对齐不可靠，易取值为空或截断，不引入错误信息。
- **下一阶段需 Ghidra/反汇编**：调用图聚类替代导入表粗分类，提升模块划分精度；
  确认高危 API 是否真正被调用（消除"具备能力但未使用"的误报）。
- **需真实样本校准**：收集一批已知良性/恶意样本，回归校准阈值与特征库。
- **流水线方向**：粗筛（本脚本，退出码 0/1/2）→ 高危模块自动交 Ghidra `trace/decompile` 深挖。

## 命令速查表（按功能分组）

### 🔍 基础检查（无需 Ghidra）
| 我想... | 用这个命令 |
|---------|-----------|
| 看文件基本信息（格式/大小/哈希） | `inspect-artifact <path>` |
| 获取应用概览（自动调 Ghidra） | `analyze <path>` |
| 看是不是 .NET 写的 | `inspect-managed-artifact <path>` |
| 看是不是 Go 写的 | `inspect-go-binary <path>` |
| 看是不是 Rust 写的 | `inspect-rust-binary <path>` |
| 看 PE 资源（图标/版本信息） | `inspect-pe-resources <path>` |
| 看 Electron 熔断配置 | `inspect-electron-fuses <exe>` |
| 诊断环境 / 列 provider | `doctor` / `providers` |

### 🔨 Ghidra Native 分析（需 Ghidra）
| 我想... | 用这个命令 |
|---------|-----------|
| 搜字符串（API名/公司名/注册表路径） | `search <path> "关键词" --kind strings --provider ghidra` |
| 搜函数名 | `search <path> "函数名" --kind procedures --provider ghidra` |
| 反编译函数看完整 dossier | `function <path> <地址> --provider ghidra` |
| 反编译只看伪代码文本 | `decompile <path> <地址> --provider ghidra` |
| 追踪特性调用关系 | `trace <path> "关键词" --provider ghidra` |
| 查交叉引用（谁调用了它） | `xrefs <path> <地址> --provider ghidra` |

### 📦 JS / Electron 应用
| 我想... | 用这个命令 |
|---------|-----------|
| 分析 JS/Electron 静态结构 | `analyze-javascript-application <path>` |
| 恢复混淆 JS 源码（⚠️ 仅 Linux） | `recover-javascript-sources <asar> <输出目录>` |

### 📱 Android / 其他
| 我想... | 用这个命令 |
|---------|-----------|
| 分析 Android APK | `inspect-android-package <apk>`（需 JADX） |
| EVM 字节码 | ⚠️ 仅 Linux x64 |
| 固件分析 | ⚠️ 仅 Linux x64（Binwalk） |

## 路由决策：先判断目标类型

根据用户提供的目标，选择对应的分析命令：

### 通用工件清单（所有格式通用）
```powershell
npx -y rea-agents@6.7.0 inspect-artifact "<文件路径>" --format json
```
- 自动识别 PE / ELF / Mach-O / ZIP / APK / IPA / DMG 等格式
- 输出文件清单、哈希、大小、格式分类
- 会自动给出下一步建议（next_probes）

### JavaScript / Electron / ASAR
```powershell
# 完整静态分析
npx -y rea-agents@6.7.0 analyze-javascript-application "<路径>" --format json

# 限定关键文件（速度快）
npx -y rea-agents@6.7.0 analyze-javascript-application "<路径>" --source-path package.json --source-path main.js --format json

# 恢复混淆源码（outputDirectory 是位置参数）
npx -y rea-agents@6.7.0 recover-javascript-sources "<asar路径>" "<输出目录>" --format json
```

### Native PE / ELF / Mach-O

**Windows 上你已装好 Ghidra 12.1.4，native 反编译完全可用。**

```powershell
# 托管代码检查（.NET / CIL，无需 Ghidra）
npx -y rea-agents@6.7.0 inspect-managed-artifact "<路径>" --format json

# Go 二进制元数据（无需 Ghidra）
npx -y rea-agents@6.7.0 inspect-go-binary "<路径>" --format json

# Electron 熔断配置
npx -y rea-agents@6.7.0 inspect-electron-fuses "<路径>" --format json

# --- Ghidra 驱动的 native 分析（第一次跑会启动 Java，较慢）---

# 搜索字符串
npx -y rea-agents@6.7.0 search "<exe路径>" "关键词" --kind strings --provider ghidra --format json

# 搜索函数名
npx -y rea-agents@6.7.0 search "<exe路径>" "函数名" --kind procedures --provider ghidra --format json

# 分析单个函数（反编译为伪代码）
# 注意：x64 PE 基址通常是 0x140000000，函数地址如 0x140002910
npx -y rea-agents@6.7.0 function "<exe路径>" 0x140002910 --provider ghidra --format json

# 保存分析快照，下次复用（避免每次重新跑 Ghidra）
npx -y rea-agents@6.7.0 search "<exe路径>" "关键词" --snapshot "$env:TEMP\rea-snapshot" --provider ghidra --format json
```

**注意：**
- Ghidra 第一次分析需要启动 JVM，可能要 1-2 分钟，耐心等
- 用 `--snapshot` 保存分析结果，后续命令复用快照，不用重新分析
- `inspect-binary-layout` 仅支持 Linux x64 ELF（用的是 pwntools，不是 Ghidra），Windows PE 用不了

**已验证实战示例（notepad.exe）：**
```powershell
# 搜 "Notepad" 字符串 → 找到 16 条匹配
# 输出包含：注册表路径、源码文件名、UWP 包名、XML Manifest 等
npx -y rea-agents@6.7.0 search "C:\Windows\System32\notepad.exe" "Notepad" --kind strings --provider ghidra --format json

# 搜 "WinMain" 函数 → 只找到 CRT 外部函数，没有 notepad 自己的入口
# 原因：没加载 PDB，用户态函数都是 FUN_xxxxxx 符号名，不是原始函数名
npx -y rea-agents@6.7.0 search "C:\Windows\System32\notepad.exe" "WinMain" --kind procedures --provider ghidra --format json
```
Ghidra 会自动加载 PE、运行自动分析、提取字符串，整个过程约 30-60 秒。

**实战经验：**
- 没有 PDB 的 Windows PE，用户函数都是 `FUN_xxxxxxxx` 符号名
- 要找主入口，可以从 Entry Point 入手，或者搜 `sub_` 开头的函数
- 外部 DLL 函数名是完整的（比如 `kernel32.dll!CreateFileW`）
- 反编译外部 thunk 函数结果很简单（就是个 jmp），要反编译用户代码得找内部 FUN_ 函数

**decompile 输出示例（已验证）：**
```
void _o__get_wide_winmain_command_line(void)
{
  /* WARNING: Could not recover jumptable at 0x000140002910. Too many branches */
  _o__get_wide_winmain_command_line();
  return;
}
```
伪代码在 JSON 的 `normalized_result` 字段里。

### Android APK
```powershell
npx -y rea-agents@6.7.0 inspect-android-package "<路径>" --format json
```
需要 Java 17+ 和 JADX。

### EVM 字节码
⚠️ 仅支持 Linux x64，Windows 不可用。
```powershell
# encoding 是位置参数
npx -y rea-agents@6.7.0 inspect-evm-interface "<hex字节码>" hex --format json
```

### 固件
⚠️ 仅 Linux x64（需 Binwalk）
```powershell
# 区域识别
npx -y rea-agents@6.7.0 inspect-firmware-regions "<镜像>" --format json

# 提取（outputDirectory 是位置参数）
npx -y rea-agents@6.7.0 extract-firmware "<镜像>" "<输出目录>" --format json
```

## 证据复用与深入查看

分析结果保存为 JSON 文件后，用 `inspect-analysis-view` 查看摘要或特定视图，
**不需要重新分析整个文件**。

### inspect-analysis-view 真实用法（已验证）

CLI 模式下必须用 **inline 方式**——把完整证据对象嵌进请求 JSON 里：

```powershell
# 第一步：分析，保存证据
npx -y rea-agents@6.7.0 inspect-artifact "C:\Windows\notepad.exe" --format json > evidence.json

# 第二步：构造视图请求（PowerShell 组装，无 BOM）
$evidence = Get-Content "evidence.json" -Raw | ConvertFrom-Json
$requestObj = @{
  source = @{ kind = "inline"; evidence = $evidence }
  view   = @{ kind = "summary" }
} | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText("view-request.json", $requestObj, [System.Text.UTF8Encoding]::new($false))

# 第三步：生成摘要视图
npx -y rea-agents@6.7.0 inspect-analysis-view "view-request.json" --format json
```

**注意事项：**
- 请求 JSON 必须是 **UTF-8 无 BOM**，PowerShell 默认 `Out-File -Encoding utf8` 带 BOM 会报错
- `source.kind` 只接受 `inline`（CLI 模式）或 `retained-evidence`（MCP session 模式）
- CLI 没有 session 状态，不能用 `retained-evidence` 引用 evidence_id

## 特性追踪

从某个关键词出发，追踪相关代码关系：

```powershell
# Native 二进制：用 trace 命令（位置参数）
npx -y rea-agents@6.7.0 trace "<exe路径>" "关键词" --provider ghidra --format json

# JS/Electron 应用：用 trace-application-feature（inputJson 模式）
# 需要构造请求 JSON，包含 source(证据)、seed(关键词)、direction(方向)
$evidence = Get-Content "analysis.json" -Raw | ConvertFrom-Json
$requestObj = @{
  source = $evidence
  seed = "ipc-channel-name"
  direction = "both"
} | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText("trace-request.json", $requestObj, [System.Text.UTF8Encoding]::new($false))

npx -y rea-agents@6.7.0 trace-application-feature "trace-request.json" --format json
```

## 版本对比

```powershell
# compare-application-versions 接收 inputJson 文件（和 inspect-analysis-view 类似）
# 需要先构造一个请求 JSON，包含 left 和 right 两个证据
$left = Get-Content "v1.json" -Raw | ConvertFrom-Json
$right = Get-Content "v2.json" -Raw | ConvertFrom-Json
$requestObj = @{
  left  = $left
  right = $right
} | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText("compare-request.json", $requestObj, [System.Text.UTF8Encoding]::new($false))

npx -y rea-agents@6.7.0 compare-application-versions "compare-request.json" --format json
```

## 工作流程

### 1. 先拿概览，再深入
```powershell
# 第一步：通用工件检查
npx -y rea-agents@6.7.0 inspect-artifact "<文件>" --format json > overview.json

# 第二步：根据 next_probes 建议，选择深入方向
# 比如提示了 inspect-managed-artifact，就接着跑那个
```

### 2. 证据持久化
每次分析输出保存到文件，后续分析引用该文件，避免重复计算。

### 3. 分阶段调查
1. **列问题清单**：把用户需求拆成可回答的问题
2. **概览先行**：先跑 `inspect-artifact` 建立全局认知
3. **聚焦深挖**：针对具体问题调用对应工具
4. **交叉验证**：静态分析结论要标注"静态推断"
5. **收尾报告**：每条结论关联证据文件路径，列出未知项

## 输出结构说明

每个 JSON 输出包含以下关键字段：

| 字段 | 说明 |
|------|------|
| `evidence_id` | 证据唯一 ID，后续命令引用 |
| `subject` | 分析对象（文件名、哈希、格式） |
| `normalized_result` | 核心分析结果 |
| `observations` | 观察到的事实 |
| `hypotheses` | 合理推断（低置信度） |
| `unexplored_branches` | 未探索的分支 |
| `next_probes` | 建议的下一步操作 |
| `limitations` | 已知限制 |

## 输出规范

每个结论必须区分：
- **观察 (Observation)**：工具直接输出的事实
- **推断 (Inference)**：基于观察的合理推导
- **未知 (Unknown)**：证据不足，无法判断

静态分析 ≠ 运行时行为。除非用户明确要求运行时观察，否则不要声称"运行时会怎样"。

## 加速技巧：用 Snapshot 避免重复分析

Ghidra 每次跑命令都要重新加载 PE + 自动分析，约 30-60 秒。
第一次跑的时候加 `--snapshot` 保存分析结果，后续命令直接复用：

```powershell
# 第一次：分析并保存快照
npx -y rea-agents@6.7.0 search "C:\app.exe" "关键词" --provider ghidra --snapshot "C:\temp\myapp-snap" --format json

# 第二次：用同一个快照，不用重新分析
npx -y rea-agents@6.7.0 function "C:\app.exe" WinMain --provider ghidra --snapshot "C:\temp\myapp-snap" --format json

# 第三次：继续搜别的，还是用同一个快照
npx -y rea-agents@6.7.0 search "C:\app.exe" "其他关键词" --kind strings --provider ghidra --snapshot "C:\temp\myapp-snap" --format json
```

同一个二进制的多次分析，一定要复用 snapshot，速度从 60 秒 → 2 秒。

**snapshot 注意事项：**
- snapshot 文件保存在本地目录，不要放系统盘临时目录（会被清理）
- 换了二进制文件必须用新的 snapshot 路径
- 同一个二进制多次跑 Ghidra 命令，用同一个 snapshot 最快

## 输出解读指南

拿到一个大 JSON，别从头读。按优先级找这几个字段：

### 第一步：看 next_probes（下一步该干嘛）
```powershell
# 用 filter-output 只看下一步建议
npx -y rea-agents@6.7.0 inspect-artifact "app.exe" --filter-output "normalized_result.next_probes,normalized_result.limitations"
```

### 第二步：看 observations（观察到的事实）
```powershell
npx -y rea-agents@6.7.0 search "app.exe" "CreateFile" --kind strings --filter-output "normalized_result[].address,normalized_result[].value"
```

### 第三步：看 limitations（已知限制）
limitations 里说"不支持"的功能，就别再试了，直接降级。

### 控制输出大小（大 JSON 专用）
```powershell
# 先看 token 总数
npx -y rea-agents@6.7.0 inspect-artifact "app.exe" --token-count

# 只取前 2000 token
npx -y rea-agents@6.7.0 inspect-artifact "app.exe" --token-limit 2000 --format json

# 从第 2000 token 开始取（分页）
npx -y rea-agents@6.7.0 inspect-artifact "app.exe" --token-offset 2000 --token-limit 2000 --format json
```

### 快速提取关键字段的 PowerShell 技巧
```powershell
# 从已保存的 JSON 里提取所有字符串值
$data = Get-Content "result.json" -Raw | ConvertFrom-Json
$data.normalized_result | Select-Object -First 10

# 只看 next_probes
$data.normalized_result.next_probes | ForEach-Object { $_.operation + " → " + $_.rationale }

# 提取所有搜索结果的地址+值（search 命令输出）
$data.normalized_result | ForEach-Object { "0x$($_.address.ToString('X')): $($_.value)" }

# 提取 limitations 列表
$data.limitations | ForEach-Object { "⚠️ $_" }
```

## 实战案例：逆向 notepad.exe

```powershell
# 第 1 步：基础信息
npx -y rea-agents@6.7.0 inspect-artifact "C:\Windows\System32\notepad.exe" --format json

# 第 2 步：.NET 检查（结果：not-managed，不是 C# 写的）
npx -y rea-agents@6.7.0 inspect-managed-artifact "C:\Windows\System32\notepad.exe" --format json

# 第 3 步：Ghidra 搜 "Notepad" 字符串 → 找到 16 条匹配
npx -y rea-agents@6.7.0 search "C:\Windows\System32\notepad.exe" "Notepad" --kind strings --provider ghidra --format json

# 第 4 步：搜 WinMain 函数 → 只找到 CRT 外部函数（没 PDB，用户函数都是 FUN_xxx）
npx -y rea-agents@6.7.0 search "C:\Windows\System32\notepad.exe" "WinMain" --kind procedures --provider ghidra --format json

# 第 5 步：反编译某个地址看伪代码
npx -y rea-agents@6.7.0 decompile "C:\Windows\System32\notepad.exe" 0x140002910 --provider ghidra --format json
```

## 故障排查

### npx 命令失败
```powershell
node --version
npx -y rea-agents@6.7.0 --version
npx -y rea-agents@6.7.0 --help
```

### 输出太大读不完
重定向到文件，然后用 Read 工具分段读取。
也可以用 `--filter-output` 只看需要的字段：
```powershell
npx -y rea-agents@6.7.0 <command> --filter-output "normalized_result.observations,normalized_result.next_probes"
```

### 缺少分析引擎
Native 反编译需要 Ghidra / IDA / Hopper，REA 不会自动安装。
如果用户没有这些工具，降级到：
- `inspect-artifact` 基础清单
- `inspect-managed-artifact` 托管代码检查
- `inspect-go-binary` Go 元数据
- 字符串搜索（用 Grep 思路）

### 平台不支持
- `inspect-binary-layout`：仅支持 Linux x64 ELF，Windows PE 不支持
- `inspect-evm-interface`：仅支持 Linux x64，Windows 不支持
- Android 分析：需要 Java 17+ 和 JADX
- 固件提取：需要 Binwalk / Unblob（Linux）
- SQLite 检查：需要 Node.js 24.15+

### 常见报错
| 报错 | 原因 | 解决 |
|------|------|------|
| `UTF-8 BOM` 报错 | PowerShell Out-File 默认带 BOM | 用 `[System.IO.File]::WriteAllText` + UTF8Encoding($false) |
| `capability_unavailable` | 平台不支持该功能 | 看 limitations 字段，降级到基础工具 |
| 输出 JSON 太大 | 完整分析结果很大 | 重定向到文件，用 Read 分段读，或 `--filter-output` |
| Ghidra 第一次跑很慢 | 启动 JVM + 自动分析 | 正常，约 30-60 秒；后续用 `--snapshot` 加速 |
| `procedure not found` | 没加载 PDB，函数名是 FUN_xxxxxx | 用地址代替函数名，或搜 `sub_` 开头的符号 |

## 参考文档

- `references/command-catalog.md` — **完整 155 个命令目录（按功能分类）**
- `references/javascript-applications.md` — JS/Electron 分析详细流程
- `references/native-and-artifacts.md` — Native 二进制与归档
- `references/android-applications.md` — Android APK 分析
- `references/runtime-observation.md` — 浏览器/Electron 运行时观察
- `references/evidence-workflows.md` — 证据管理与分页
- `references/connection-and-recovery.md` — CLI 故障恢复
