# Evidence and Workflow Guide — CLI 版

## 输出结构说明

每个 JSON 输出的核心字段：

| 字段 | 说明 |
|------|------|
| `evidence_id` | 证据唯一 ID |
| `subject` | 分析对象（文件名、哈希、格式） |
| `normalized_result` | 核心分析结果 |
| `observations` | 观察到的事实 |
| `hypotheses` | 合理推断（低置信度） |
| `unexplored_branches` | 未探索的分支 |
| `next_probes` | 建议的下一步操作 |
| `limitations` | 已知限制 |

## 证据保存规范

每次分析输出保存到文件：
```powershell
npx -y rea-agents@6.7.0 inspect-artifact "C:\app.exe" --format json > evidence.json
```

## 证据导入导出

```powershell
# 导出证据包
npx -y rea-agents@6.7.0 evidence-export --format json

# 导入证据包（验证并加载本地证据）
npx -y rea-agents@6.7.0 evidence-import "evidence-bundle.json" --format json
```

## inspect-analysis-view 真实用法（已验证）

CLI 模式下用 **inline 方式**查看摘要视图：

```powershell
# 读取已有证据，构造视图请求
$evidence = Get-Content "evidence.json" -Raw | ConvertFrom-Json
$requestObj = @{
  source = @{ kind = "inline"; evidence = $evidence }
  view   = @{ kind = "summary" }
} | ConvertTo-Json -Depth 10

# 写无 BOM 的 UTF-8 文件
[System.IO.File]::WriteAllText("view-request.json", $requestObj, [System.Text.UTF8Encoding]::new($false))

# 生成摘要
npx -y rea-agents@6.7.0 inspect-analysis-view "view-request.json" --format json
```

**注意：**
- 请求 JSON 必须 UTF-8 无 BOM
- `source.kind` 只接受 `inline`（CLI 模式）
- CLI 没有 session 状态，不能用 `retained-evidence`

## 版本对比
```powershell
# 通用对比（两个证据包文件）
npx -y rea-agents@6.7.0 compare "v1.json" "v2.json" --format json

# JS 应用版本对比（需要构造 inputJson）
$left = Get-Content "v1.json" -Raw | ConvertFrom-Json
$right = Get-Content "v2.json" -Raw | ConvertFrom-Json
$requestObj = @{ left = $left; right = $right } | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText("compare-request.json", $requestObj, [System.Text.UTF8Encoding]::new($false))

npx -y rea-agents@6.7.0 compare-application-versions "compare-request.json" --format json
```

## 结论格式

每条结论必须区分：

| 类型 | 说明 |
|------|------|
| 观察 Observation | 工具直接输出的事实 |
| 推断 Inference | 基于观察的合理推导 |
| 未知 Unknown | 证据不足，无法判断 |

静态分析 ≠ 运行时行为。

## 调查流程

1. **列问题清单**：把用户需求拆成可回答的具体问题
2. **概览先行**：先跑 `inspect-artifact` 建立全局认知
3. **聚焦深挖**：针对具体问题调用对应工具
4. **交叉验证**：不同工具的结果互相印证
5. **收尾报告**：每条结论关联证据文件，列出未知项

## 输出太大处理

1. 用 `--filter-output` 只看需要的字段
2. 重定向到文件，用 Read 工具分段读
3. 用 PowerShell `ConvertFrom-Json` 提取关键字段
