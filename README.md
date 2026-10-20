# Reverse Engineer Anything (REA) — 豆包 CLI 适配版

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
| JS/Electron 分析 | `analyze-javascript-application <path>` | Web 应用静态分析 |

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

## 引用

- 原始项目：[morluto/rea](https://github.com/morluto/rea)
- npm 包：[rea-agents](https://www.npmjs.com/package/rea-agents)

## License

MIT — 见 [LICENSE](./LICENSE)
