# Reverse Engineer Anything (REA) — 豆包 CLI 适配版

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Node](https://img.shields.io/badge/node-18%2B-green.svg)
![Ghidra](https://img.shields.io/badge/ghidra-11%2B-orange.svg)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey.svg)

> 基于 [rea-agents](https://www.npmjs.com/package/rea-agents) 6.7.0 的逆向工程 Skill，深度改造为豆包/字节系 Agent 原生 CLI 驱动版。

## 这是什么？

原版 REA 是 **MCP 架构**（依赖 207 个 MCP 工具，需要 MCP Server 连接），在不支持 MCP Client 的 Agent 环境里完全跑不起来。

本仓库把它**重写为纯 CLI 驱动版**：
- 所有分析通过 `npx -y rea-agents@6.7.0 <command>` 直接调用
- 不依赖 MCP Server 注册
- 适配 Windows PowerShell 执行环境
- 内置 Ghidra 12.1.4 native 反编译支持

## 快速开始

### 前置要求
- Node.js 18+（推荐 22.x）
- Ghidra 11+（native 反编译用，可选）
- JDK 21+（Ghidra 依赖）

### 第一步：环境检查
```powershell
npx -y rea-agents@6.7.0 doctor --format json
```

### 第二步：拿到一个陌生 exe，5 步走
```powershell
# 1. 基础信息（格式/大小/哈希）
npx -y rea-agents@6.7.0 inspect-artifact "C:\path\to\app.exe" --format json

# 2. 是不是 .NET 写的
npx -y rea-agents@6.7.0 inspect-managed-artifact "C:\path\to\app.exe" --format json

# 3. 搜关键字符串
npx -y rea-agents@6.7.0 search "C:\path\to\app.exe" "CreateFile" --kind strings --provider ghidra --format json

# 4. 搜函数名
npx -y rea-agents@6.7.0 search "C:\path\to\app.exe" "WinMain" --kind procedures --provider ghidra --format json

# 5. 反编译某个函数看伪代码
npx -y rea-agents@6.7.0 decompile "C:\path\to\app.exe" 0x140002910 --provider ghidra --format json
```

## 核心功能（Windows 已验证）

| 功能 | 命令 | 说明 |
|------|------|------|
| 通用工件检查 | `inspect-artifact <path>` | 自动识别 PE/ELF/Mach-O/ZIP/APK |
| 应用概览分析 | `analyze <path>` | 自动调 Ghidra 做完整分析 |
| .NET 检查 | `inspect-managed-artifact <path>` | CIL / 托管元数据 |
| Go 二进制 | `inspect-go-binary <path>` | Go 模块和依赖 |
| Rust 二进制 | `inspect-rust-binary <path>` | cargo-auditable 依赖列表 |
| PE 资源 | `inspect-pe-resources <path>` | 图标/版本信息/对话框 |
| Electron 熔断 | `inspect-electron-fuses <exe>` | 熔断开关检查 |
| 字符串搜索 | `search <path> "关键词" --kind strings --provider ghidra` | Ghidra 驱动 |
| 函数搜索 | `search <path> "关键词" --kind procedures --provider ghidra` | Ghidra 驱动 |
| 伪代码反编译 | `decompile <path> <地址> --provider ghidra` | 反编译为 C 伪代码 |
| 交叉引用 | `xrefs <path> <地址> --provider ghidra` | 谁调用了这个函数 |
| 特性追踪 | `trace <path> "关键词" --provider ghidra` | 追踪代码关系 |
| EXE 模块化粗筛 / 风险打分 | `python tools/pe_module_scan.py <exe> --report r.md [--quiet] [--min-confidence high]` | 导入表+字符串归类模块（注入/键盘记录/提权/凭据窃取/反调试/反沙盒/勒索/外泄等）、风险打分、签名/加壳/类型识别、外联证据、高危置顶、中文报告（零依赖，Ghidra 前第一层；`--quiet` 精简结论，退出码 0/1/2 供流水线） |
| JS/Electron 分析 | `analyze-javascript-application <path>` | Web 应用静态分析 |

### 本地零依赖粗筛（Ghidra 前第一层，无需 Node/Ghidra）

```powershell
# 基础扫描 + 中文 Markdown 报告 + 结构化 JSON
python tools\pe_module_scan.py "C:\path\app.exe" --report r.md --json r.json

# 流水线/CI：只打印风险结论，靠退出码判定（0 安全 / 1 可疑 / 2 高危 / 3 非PE）
python tools\pe_module_scan.py "C:\path\app.exe" --quiet

# 只看高置信模块（至少命中 2 个精确 API；纯字符串高危模块始终保留）
python tools\pe_module_scan.py "C:\path\app.exe" --min-confidence high

# 批量分诊：递归扫描目录下 exe/dll，按风险分降序排名，--report 落盘 Markdown 总表
python tools\pe_module_scan.py --batch "C:\downloads" --report rank.md

# 基线巡检：--baseline 存哈希+分数，复扫标注 新增/已替换/风险上升/已见
python tools\pe_module_scan.py --batch "C:\downloads" --baseline db.json
```

参数：`--report` 报告路径、`--json` 结构化结果（顶层含 `network_evidence` 外联证据）、
`--quiet` 精简输出、`--min-confidence high|medium|low`、`--batch <目录>` 批量分诊排名、
`--baseline <json>` 基线指纹复扫对比、`--version`。单文件 EXE 用 `tools\build_exe.bat` 打包。

能力：导入表精确 API 匹配 + 字符串粗归类，覆盖注入（含原生 NtWriteVirtualMemory /
NtUnmapViewOfSection 进程空洞）、提权令牌/模拟、键盘记录、录音摄像头、截屏录屏、
凭据窃取、反取证（含现代 EvtClearLog）、破坏安全软件、反调试、反沙盒、勒索、
数据外泄、下载执行、持久化；报告含节区熵与 X/R/W 权限表（高熵/RWX 标⚠️）、
类型识别（.NET/Go/Electron/NW.js/CEF/Node/Python/加壳）、PE 头解析（EXE/DLL、GUI/控制台
子系统、编译时间戳、签名）、外联 URL/IP/域名过滤（公网列出并建议核查，内网/回环/占位域名
归入参考不计可疑），并对“注入+外联”“注入+持久化”“凭据+外联”等高危组合给联动判断；
非 PE（ELF/Mach-O/Java/ZIP）识别魔数并给出原版 rea-agents 对应命令引导。

## 命令模式说明

REA CLI 有两种命令模式，别搞混：

| 模式 | 特点 | 示例 |
|------|------|------|
| **直接分析模式** | 传入文件路径，直接分析 | `inspect-artifact <path>` |
| **证据二次分析模式** | 传入 inputJson 文件，基于已有证据做分析 | `inspect-analysis-view <request.json>` |

证据二次分析模式需要用 PowerShell 组装 JSON 请求文件，**必须 UTF-8 无 BOM**（PowerShell 默认 `Out-File -Encoding utf8` 带 BOM 会报错）：

```powershell
[System.IO.File]::WriteAllText("request.json", $json, [System.Text.UTF8Encoding]::new($false))
```

## 加速技巧：Snapshot

Ghidra 第一次跑要 30-60 秒（启动 JVM + 自动分析）。
第一次跑的时候加 `--snapshot` 保存分析结果，后续命令直接复用，速度从 60 秒 → 2 秒。

```powershell
# 第一次：分析并保存快照
npx -y rea-agents@6.7.0 search "app.exe" "关键词" --provider ghidra --snapshot "C:\temp\snap" --format json

# 第二次：复用快照
npx -y rea-agents@6.7.0 decompile "app.exe" 0x140002910 --provider ghidra --snapshot "C:\temp\snap" --format json
```

## 平台支持矩阵

| 功能 | Windows | Linux | macOS |
|------|---------|-------|-------|
| inspect-artifact | ✅ | ✅ | ✅ |
| inspect-managed-artifact | ✅ | ✅ | ✅ |
| inspect-go-binary | ✅ | ✅ | ✅ |
| inspect-rust-binary | ✅ | ✅ | ✅ |
| inspect-pe-resources | ✅ | ⚠️ | ⚠️ |
| Ghidra native 分析 | ✅ | ✅ | ✅ |
| inspect-binary-layout | ❌ | ✅ | ❌ |
| inspect-evm-interface | ❌ | ✅ | ❌ |
| SQLite 检查 | ⚠️ Node 24+ | ⚠️ Node 24+ | ⚠️ Node 24+ |
| 固件提取 | ❌ | ✅ | ❌ |
| Hopper | ❌ | ❌ | ✅ |
| JADX (Android) | 需手动配置 | 需手动配置 | 需手动配置 |

## 文件结构

```
reverse-engineer-anything/
├── SKILL.md                          # 主入口文件
├── README.md                         # 本文件
├── LICENSE                          # MIT 许可证
├── .gitignore
├── tools/
│   ├── pe_module_scan.py            # EXE 模块化粗筛/风险打分（零依赖本地脚本）
│   ├── test_scan.py                 # 回归测试基线（python tools/test_scan.py，40 项断言）
│   ├── build_exe.bat                # PyInstaller 单文件 EXE 打包脚本
│   └── ANALYSIS_VM.md               # 隔离虚拟机(dc)真实样本分析操作手册
└── references/
    ├── command-catalog.md           # 完整 153 个命令分类索引
    ├── javascript-applications.md   # JS/Electron 分析详细流程
    ├── native-and-artifacts.md      # Native 二进制与归档
    ├── android-applications.md      # Android APK 分析
    ├── runtime-observation.md        # 浏览器/Electron 运行时观察
    ├── evidence-workflows.md        # 证据管理与分页
    └── connection-and-recovery.md   # CLI 故障恢复
```

## 安装到豆包/Claude Code/Codex

把整个文件夹放到你的 Agent skill 目录下即可：
- 豆包 user_skills：`~/.doubao/agent_mode/workspace/.user_skills/`
- Claude Code：`~/.claude/skills/`
- Codex：`~/.codex/skills/`

## 作者

**Lai123** — 豆包 CLI 适配版改造者

## 引用

- 原始项目：[morluto/rea](https://github.com/morluto/rea)
- npm 包：[rea-agents](https://www.npmjs.com/package/rea-agents)
- 官方网站：https://rea.tools

## License

MIT — 见 [LICENSE](./LICENSE)
