# Connection and Task Recovery — CLI 版

## 快速诊断
```powershell
# 检查 Node.js
node --version
npx --version

# 检查 REA 版本
npx -y rea-agents@6.7.0 --version

# 列出所有命令
npx -y rea-agents@6.7.0 --help

# 完整环境诊断
npx -y rea-agents@6.7.0 doctor --format json

# 列出可用 provider
npx -y rea-agents@6.7.0 providers --format json

# 列出所有能力和副作用
npx -y rea-agents@6.7.0 capabilities --format json

# 配置集成（自动安装可选 provider，需确认）
npx -y rea-agents@6.7.0 setup --yes

# 获取全部命令的 LLM 友好清单
npx -y rea-agents@6.7.0 --llms

# 查看某个命令的 JSON Schema（参数详细说明）
npx -y rea-agents@6.7.0 inspect-artifact --schema
```

## 你电脑上的环境状态（已验证）

| 组件 | 状态 | 路径/版本 |
|------|------|-----------|
| Node.js | ✅ 可用 | v22.23.2 |
| Ghidra | ✅ 完全健康 | C:\Tools\ghidra_12.1.4_PUBLIC |
| Java | ✅ 可用 | JDK 21.0.12 |
| Hopper | ❌ 不可用 | macOS 专用 |
| IDA | ❌ 未配置 | 需设置 REA_IDA_MCP_CONFIG |
| JADX | ❌ 未配置 | 需设置 REA_JADX_MCP_JAR |
| Kuna | ❌ 未配置 | 需设置 REA_KUNA_COMMAND |
| SQLite 检查 | ❌ 不可用 | 需 Node 24.15+ |

**doctor 结果：环境整体健康（healthy: true）**
CLI 命令总数：153 个（MCP 工具：207 个）

## 常见问题与解决

| 现象 | 原因 | 解决 |
|------|------|------|
| `npx: command not found` | Node 未装或未入 PATH | 安装 Node.js 18+ |
| JSON 带 BOM 报错 | PowerShell Out-File 默认带 BOM | 用 `[System.IO.File]::WriteAllText` + UTF8Encoding($false) |
| Ghidra 命令第一次很慢 | 启动 JVM 需要时间 | 耐心等，后续用 `--snapshot` 加速 |
| `capability_unavailable` | 平台不支持该功能 | 降级到基础工具 |
| 输出 JSON 太大读不完 | 完整分析结果很大 | 重定向到文件，用 Read 分段读 |

## 输出处理规范

所有命令加 `--format json`，输出重定向到临时文件：

```powershell
$out = "$env:TEMP\rea-output.json"
npx -y rea-agents@6.7.0 <command> <args> --format json > $out
# 然后用 Read 工具读取
```

## 降级策略

当高级分析不可用时，用基础工具完成能做的部分：

- **JS/Electron**：用 Read / Grep 直接读源码、package.json
- **Native PE**：用 `inspect-artifact` 基础清单 + `search` 搜字符串
- **APK**：直接当 ZIP 解压，看 AndroidManifest.xml
- **归档包**：用 PowerShell `Expand-Archive` 解压后看文件结构

明确告诉用户哪些是 REA 高级分析的结果，哪些是基础工具的观察。
