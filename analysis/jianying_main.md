# EXE 模块化分析报告：JianyingPro.exe

> 生成时间：2026-10-21 15:14:20　|　分析方式：静态粗筛（未运行程序）

## ⚠️ 高危速览（优先深挖）

- **提权 / 令牌操作**（API 8 / 字符串 0）— 打开进程令牌、调整特权（如 SeDebugPrivilege）

## 一、样本信息

| 项 | 值 |
|---|---|
| 文件 | JianyingPro.exe |
| 大小 | 5,348,376 字节 |
| 架构 | x64 (PE32+) |
| 类型 | EXE 可执行文件 |
| 界面子系统 | GUI 图形界面 |
| 编译时间戳 | 2026-08-04 09:22 UTC |
| SHA-256 | `bf3f9475bfccce62a1ea7a83643b7aac8e2f0c8734f3efb0b4f5b7c301c93178` |
| 导入函数数 | 392 |
| 数字签名 | 已签名 |
| 节区数 | 12 |

**节区明细（熵≥7.0 或 RWX 标⚠️）：**

| 节区 | 熵 | 权限(X/R/W) | 原始大小 |
|---|---|---|---|
| .text | 5.74 | XR- | 3,245,056 |
| .rdata | 4.29 | -R- | 1,304,064 |
| .data | 2.64 | -RW | 69,632 |
| .pdata | 6.0 | -R- | 163,328 |
| .idata | 3.98 | -R- | 19,456 |
| .didat | 1.37 | -RW | 2,048 |
| minATL | 0.0 | -R- | 1,024 |
| .tls | 0.01 | -RW | 1,024 |
| .00cfg | 0.35 | -R- | 512 |
| _RDATA | 1.42 | -R- | 1,024 |
| .rsrc | 3.67 | -R- | 496,640 |
| .reloc | 3.36 | -R- | 30,208 |

| 类型/运行时 | 原生 C/C++ (未检出托管/运行时) |

## 二、风险评分

**总分：19 / 100　等级：安全 / 低关注**

> 样本已签名，系统/厂商库普遍导出高危 API，已对原始分做 0.35 减免，仅作参考。

### 高危能力命中（计入评分）

| 命中 API | 类别 | 分值 | 说明 |
|---|---|---|---|
| `ADVAPI32.dll!AdjustTokenPrivileges` | 提权 | +15 | 调整令牌特权（可用于提权） |
| `ADVAPI32.dll!ImpersonateLoggedOnUser` | 提权 | +10 | 模拟已登录用户令牌（会话劫持/提权） |
| `ADVAPI32.dll!CreateProcessAsUserW` | 提权 | +10 | 以其他用户身份创建进程（提权/横向移动） |
| `ADVAPI32.dll!SetThreadToken` | 提权 | +8 | 给线程挂上模拟令牌（会话劫持） |
| `SHELL32.dll!ShellExecuteW` | 执行 | +6 | 外壳启动外部程序 |
| `ADVAPI32.dll!LookupPrivilegeValueW` | 提权 | +5 | 查询特权（常配合提权） |

### 运行库常见项（仅提示，不计分）

- `KERNEL32.dll!IsDebuggerPresent` — 检测调试器（运行库常见，需确认是否主动调用）
- `ADVAPI32.dll!DuplicateTokenEx` — 复制令牌（管理工具常见，需确认是否模拟提权）
- `ADVAPI32.dll!OpenProcessToken` — 打开进程令牌（运行库常见）

## 三、功能模块清单（先选模块，再深入）

| # | 模块 | 置信度 | 精确API | 字符串 | 说明 |
|---|---|---|---|---|---|
| 1 | **提权 / 令牌操作** ⚠️ | 高 | 8 | 0 | 打开进程令牌、调整特权（如 SeDebugPrivilege） |
| 2 | **进程管理** | 高 | 9 | 0 | 创建、枚举、结束其他进程 |
| 3 | **文件读写** | 高 | 8 | 0 | 创建/读取/写入/删除/复制文件 |
| 4 | **动态加载 / 延迟绑定** | 高 | 4 | 0 | 运行时 LoadLibrary + GetProcAddress 取函数，可规避静态导入表（常见于恶意程序） |
| 5 | **图形界面** | 高 | 4 | 0 | 窗口、对话框、消息框等 UI 能力 |
| 6 | **注册表读写** | 高 | 3 | 0 | 打开/创建/读写/删除注册表键值 |
| 7 | **自启动 / 持久化** | 低（仅弱字符串） | 0 | 1 | 写入 Run 键、启动目录、计划任务等驻留手段（需命中驻留路径字符串） |

### 提权 / 令牌操作（高置信）　⚠️优先深挖

**命中导入 API：**
- `ADVAPI32.dll!ImpersonateLoggedOnUser`
- `ADVAPI32.dll!DuplicateToken`
- `ADVAPI32.dll!LookupPrivilegeValueW`
- `ADVAPI32.dll!ImpersonateSelf`
- `ADVAPI32.dll!AdjustTokenPrivileges`
- `ADVAPI32.dll!SetThreadToken`
- `ADVAPI32.dll!SetTokenInformation`
- `ADVAPI32.dll!CreateProcessAsUserW`

> 深挖：在 Ghidra 中定位 `ImpersonateLoggedOnUser`，用 xrefs 找调用处、decompile 看伪代码；或用 REA CLI：`trace "C:\Users\lai\JianyingPro\JianyingPro.exe" "ImpersonateLoggedOnUser" --provider ghidra`

**相关库已导入（弱佐证）：** ADVAPI32.dll

### 进程管理（高置信）

**命中导入 API：**
- `KERNEL32.dll!TerminateProcess`
- `KERNEL32.dll!CreateProcessW`
- `KERNEL32.dll!Process32NextW`
- `KERNEL32.dll!Process32FirstW`
- `KERNEL32.dll!CreateToolhelp32Snapshot`
- `KERNEL32.dll!OpenProcess`
- `ADVAPI32.dll!CreateProcessAsUserW`
- `SHELL32.dll!ShellExecuteW`
- …另有 1 条

> 深挖：在 Ghidra 中定位 `TerminateProcess`，用 xrefs 找调用处、decompile 看伪代码；或用 REA CLI：`trace "C:\Users\lai\JianyingPro\JianyingPro.exe" "TerminateProcess" --provider ghidra`

**相关库已导入（弱佐证）：** PSAPI.DLL

### 文件读写（高置信）

**命中导入 API：**
- `KERNEL32.dll!GetTempPathW`
- `KERNEL32.dll!CopyFileW`
- `KERNEL32.dll!MoveFileW`
- `KERNEL32.dll!WriteFile`
- `KERNEL32.dll!ReadFile`
- `KERNEL32.dll!CreateFileW`
- `KERNEL32.dll!FindFirstFileW`
- `KERNEL32.dll!DeleteFileW`

> 深挖：在 Ghidra 中定位 `GetTempPathW`，用 xrefs 找调用处、decompile 看伪代码；或用 REA CLI：`trace "C:\Users\lai\JianyingPro\JianyingPro.exe" "GetTempPathW" --provider ghidra`

**相关库已导入（弱佐证）：** KERNEL32.dll, SHELL32.dll, SHLWAPI.dll

### 动态加载 / 延迟绑定（高置信）

**命中导入 API：**
- `KERNEL32.dll!LoadLibraryExW`
- `KERNEL32.dll!LoadLibraryW`
- `KERNEL32.dll!GetProcAddress`
- `KERNEL32.dll!LoadLibraryExA`

> 深挖：在 Ghidra 中定位 `LoadLibraryExW`，用 xrefs 找调用处、decompile 看伪代码；或用 REA CLI：`trace "C:\Users\lai\JianyingPro\JianyingPro.exe" "LoadLibraryExW" --provider ghidra`

**相关库已导入（弱佐证）：** KERNEL32.dll

### 图形界面（高置信）

**命中导入 API：**
- `USER32.dll!DispatchMessageW`
- `USER32.dll!DefWindowProcW`
- `USER32.dll!RegisterClassExW`
- `USER32.dll!CreateWindowExW`

> 深挖：在 Ghidra 中定位 `DispatchMessageW`，用 xrefs 找调用处、decompile 看伪代码；或用 REA CLI：`trace "C:\Users\lai\JianyingPro\JianyingPro.exe" "DispatchMessageW" --provider ghidra`

**相关库已导入（弱佐证）：** USER32.dll, GDI32.dll

### 注册表读写（高置信）

**命中导入 API：**
- `ADVAPI32.dll!RegDeleteValueW`
- `ADVAPI32.dll!RegOpenKeyW`
- `ADVAPI32.dll!RegCloseKey`

> 深挖：在 Ghidra 中定位 `RegDeleteValueW`，用 xrefs 找调用处、decompile 看伪代码；或用 REA CLI：`trace "C:\Users\lai\JianyingPro\JianyingPro.exe" "RegDeleteValueW" --provider ghidra`

**相关库已导入（弱佐证）：** ADVAPI32.dll

### 自启动 / 持久化（低（仅弱字符串）置信）

**命中字符串（节选）：**
- `wmic`

## 四、结论与下一步

### 总体判断（自动生成，仅供第一层参考）

- 未命中显著高危能力，静态层面风险低。
- 重点模块：提权 / 令牌操作，建议优先对这些模块做调用链深挖。

- 本报告基于**导入表 + 字符串**静态粗筛，属于第一层判断，**不等于运行时行为**；命中高危 API 只代表“具备该能力”，是否真正使用需结合反编译确认。
- 建议：从上表选择你关心的模块，再用 Ghidra `trace` / `decompile` / `xrefs` 对该模块对应 API 做调用链深挖。
- 静态推断条目请在最终结论中标注“静态推断”，勿直接判定为恶意。
