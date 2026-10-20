# JavaScript and Electron Application Analysis — CLI 版

## 基础分析
```powershell
# 完整静态分析
npx -y rea-agents@6.7.0 analyze-javascript-application "<路径>" --format json > analysis.json

# 限定关键文件（速度快很多）
npx -y rea-agents@6.7.0 analyze-javascript-application "<路径>" --source-path package.json --source-path main.js --format json

# 先拿摘要
npx -y rea-agents@6.7.0 analyze-javascript-application "<路径>" --detail summary --format json
```

## 源码恢复
```powershell
# outputDirectory 是位置参数
npx -y rea-agents@6.7.0 recover-javascript-sources "<asar路径>" "<输出目录>" --format json
```
需要 Wakaru（Linux x64）。Windows 上不可用，降级到直接读源文件。

**Windows 注意事项：**
- `analyze-javascript-application` 纯 Node.js 实现，Windows 可用
- 大 Electron 应用分析可能较慢，建议先 `--detail summary`

## 特性追踪
```powershell
# inputJson 模式：构造请求 JSON
$evidence = Get-Content "analysis.json" -Raw | ConvertFrom-Json
$requestObj = @{
  source = $evidence
  seed = "ipc-channel-name"
  direction = "both"
} | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText("trace-request.json", $requestObj, [System.Text.UTF8Encoding]::new($false))

npx -y rea-agents@6.7.0 trace-application-feature "trace-request.json" --format json
```
从某个关键词（IPC 通道名、API 名）追踪相关代码关系。

## 版本对比
```powershell
# 需要构造 inputJson 文件，包含 left 和 right 两个证据对象
# 和 inspect-analysis-view 的调用方式类似
$left = Get-Content "v1.json" -Raw | ConvertFrom-Json
$right = Get-Content "v2.json" -Raw | ConvertFrom-Json
$requestObj = @{ left = $left; right = $right } | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText("compare-request.json", $requestObj, [System.Text.UTF8Encoding]::new($false))

npx -y rea-agents@6.7.0 compare-application-versions "compare-request.json" --format json
```

## inspect-analysis-view 查看详情
分析完成后，用 inline 方式查看摘要视图：

```powershell
$evidence = Get-Content "analysis.json" -Raw | ConvertFrom-Json
$requestObj = @{
  source = @{ kind = "inline"; evidence = $evidence }
  view   = @{ kind = "summary" }
} | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText("view-request.json", $requestObj, [System.Text.UTF8Encoding]::new($false))
npx -y rea-agents@6.7.0 inspect-analysis-view "view-request.json" --format json
```

## 静态分析边界

以下都是**静态语法观察**，不等于运行时行为：
- BrowserWindow 配置
- preload.js 的 contextBridge 暴露
- IPC 注册（`ipcMain.handle(...)` 静态声明）
- `.node` 原生模块引用

不要从静态分析声称"这个接口一定会被调用"。

## 输出太大处理
1. 用 `--detail summary` 先跑摘要
2. 用 `--filter-output` 只看关键字段
3. 重定向到文件，用 Read 分段读
