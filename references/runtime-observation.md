# Browser and Electron Runtime Observation — CLI 版

> 注意：运行时观察类功能主要依赖 MCP 工具，纯 CLI 模式下能力有限。

## CLI 模式下可用的离线分析

```powershell
# Electron 熔断配置（静态检查）
npx -y rea-agents@6.7.0 inspect-electron-fuses "<exe路径>" --format json
```

## 运行时观察（需要 MCP，CLI 不支持）

以下功能需要 MCP server 连接浏览器/Electron 实例，纯 CLI 模式下不可用：
- `list_browser_targets` — 列出浏览器页面
- `capture_browser_scenario` — 执行浏览器操作场景
- `observe_web_session` — 被动观察网页会话
- `list_electron_targets` — 列出 Electron 实例

降级方案：
- 用 Read / Grep 直接读应用源码
- 分析预加载脚本和 IPC 注册
- 查看配置文件和日志

## 静态 + 运行时交叉验证

当同时有静态分析证据和运行时观察时，用
`reconcile-javascript-runtime` 做对账。
纯 CLI 模式下手动对账：
1. 对比静态分析里的源文件哈希和运行时加载的脚本哈希
2. 哈希一致 → 静态分析可信
3. 哈希不一致 → 以运行时实际加载的为准

## 离线抓包分析

离线抓包文件可以用 CLI 分析（⚠️ 具体平台支持需验证）：

```powershell
# HAR 文件（format 是位置参数）
npx -y rea-agents@6.7.0 inspect-web-network-capture "<文件>" har --format json

# PCAP
npx -y rea-agents@6.7.0 inspect-pcap-capture "<文件>" --format json
```

Windows 上如果报 capability_unavailable，降级到直接读文件或用 Wireshark。

## 边界说明

- 被动观察 ≠ 自动点击操作
- 静态分析结论不等于运行时行为
