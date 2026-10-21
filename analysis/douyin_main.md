# EXE 模块化分析报告：douyin.exe

> 生成时间：2026-10-21 15:28:30　|　分析方式：静态粗筛（未运行程序）

## ⚠️ 高危速览（优先深挖）

- **进程注入（高危）**（API 5 / 字符串 0）— 向其他进程分配内存并写入代码、远程建线程

## 一、样本信息

| 项 | 值 |
|---|---|
| 文件 | douyin.exe |
| 大小 | 2,754,424 字节 |
| 架构 | x64 (PE32+) |
| 类型 | EXE 可执行文件 |
| 界面子系统 | GUI 图形界面 |
| 编译时间戳 | 2026-09-10 16:22 UTC |
| SHA-256 | `e1e4b60e42a1e8026f5774e2a56791213f30f1bbb25a670c27ccb16827bdc9d5` |
| 导入函数数 | 250 |
| 数字签名 | 已签名 |
| 节区数 | 9 |
| ⚠️ 高熵节区（可能压缩/加密/加壳） | .rsrc(熵7.75) |

**节区明细（熵≥7.0 或 RWX 标⚠️）：**

| 节区 | 熵 | 权限(X/R/W) | 原始大小 |
|---|---|---|---|
| .text | 6.58 | XR- | 1,808,896 |
| .rdata | 5.95 | -R- | 759,808 |
| .data | 1.39 | -RW | 60,928 |
| .pdata | 6.12 | -R- | 66,560 |
| .fptable | 0.0 | -RW | 512 |
| .tls | 0.3 | -RW | 512 |
| _RDATA | 4.22 | -R- | 512 |
| .rsrc ⚠️ | 7.75 | -R- | 36,352 |
| .reloc | 5.37 | -R- | 7,168 |

| 类型/运行时 | 原生 C/C++ (未检出托管/运行时) |

## 二、风险评分

**总分：25 / 100　等级：低危（需关注）**

> 样本已签名，系统/厂商库普遍导出高危 API，已对原始分做 0.35 减免，仅作参考。

### 高危能力命中（计入评分）

| 命中 API | 类别 | 分值 | 说明 |
|---|---|---|---|
| `KERNEL32.dll!CreateRemoteThread` | 进程注入 | +25 | 向远程进程创建线程（代码注入经典手法） |
| `KERNEL32.dll!WriteProcessMemory` | 进程注入 | +15 | 向远程进程写入内存（配合注入） |
| `KERNEL32.dll!VirtualAllocEx` | 进程注入 | +10 | 在远程进程分配内存 |
| `KERNEL32.dll!ReadProcessMemory` | 进程注入 | +8 | 读取远程进程内存（窃密/注入辅助） |
| `KERNEL32.dll!VirtualProtectEx` | 进程注入 | +8 | 远程进程修改内存保护（配合注入） |
| `KERNEL32.dll!SetDllDirectoryW` | DLL劫持 | +6 | 设置 DLL 搜索目录（DLL 劫持/侧载） |

### 运行库常见项（仅提示，不计分）

- `KERNEL32.dll!IsDebuggerPresent` — 检测调试器（运行库常见，需确认是否主动调用）

## 三、功能模块清单（先选模块，再深入）

| # | 模块 | 置信度 | 精确API | 字符串 | 说明 |
|---|---|---|---|---|---|
| 1 | **进程注入（高危）** ⚠️ | 高 | 5 | 0 | 向其他进程分配内存并写入代码、远程建线程 |
| 2 | **网络通信** | 高 | 10 | 0 | 联网、收发数据、HTTP 请求、DNS 解析能力 |
| 3 | **文件读写** | 高 | 7 | 0 | 创建/读取/写入/删除/复制文件 |
| 4 | **进程管理** | 高 | 5 | 0 | 创建、枚举、结束其他进程 |
| 5 | **动态加载 / 延迟绑定** | 高 | 5 | 0 | 运行时 LoadLibrary + GetProcAddress 取函数，可规避静态导入表（常见于恶意程序） |

### 进程注入（高危）（高置信）　⚠️优先深挖

**命中导入 API：**
- `KERNEL32.dll!CreateRemoteThread`
- `KERNEL32.dll!ReadProcessMemory`
- `KERNEL32.dll!VirtualAllocEx`
- `KERNEL32.dll!VirtualProtectEx`
- `KERNEL32.dll!WriteProcessMemory`

> 深挖：在 Ghidra 中定位 `CreateRemoteThread`，用 xrefs 找调用处、decompile 看伪代码；或用 REA CLI：`trace "C:\Program Files (x86)\ByteDance\douyin\douyin.exe" "CreateRemoteThread" --provider ghidra`

**相关库已导入（弱佐证）：** KERNEL32.dll

### 网络通信（高置信）

**命中导入 API：**
- `WINHTTP.dll!WinHttpAddRequestHeaders`
- `WINHTTP.dll!WinHttpCloseHandle`
- `WINHTTP.dll!WinHttpConnect`
- `WINHTTP.dll!WinHttpOpen`
- `WINHTTP.dll!WinHttpOpenRequest`
- `WINHTTP.dll!WinHttpQueryDataAvailable`
- `WINHTTP.dll!WinHttpReadData`
- `WINHTTP.dll!WinHttpReceiveResponse`
- …另有 2 条

> 深挖：在 Ghidra 中定位 `WinHttpAddRequestHeaders`，用 xrefs 找调用处、decompile 看伪代码；或用 REA CLI：`trace "C:\Program Files (x86)\ByteDance\douyin\douyin.exe" "WinHttpAddRequestHeaders" --provider ghidra`

**相关库已导入（弱佐证）：** WINHTTP.dll, IPHLPAPI.DLL

### 文件读写（高置信）

**命中导入 API：**
- `KERNEL32.dll!CopyFileW`
- `KERNEL32.dll!CreateFileA`
- `KERNEL32.dll!CreateFileW`
- `KERNEL32.dll!DeleteFileW`
- `KERNEL32.dll!GetTempPathW`
- `KERNEL32.dll!ReadFile`
- `KERNEL32.dll!WriteFile`

> 深挖：在 Ghidra 中定位 `CopyFileW`，用 xrefs 找调用处、decompile 看伪代码；或用 REA CLI：`trace "C:\Program Files (x86)\ByteDance\douyin\douyin.exe" "CopyFileW" --provider ghidra`

**相关库已导入（弱佐证）：** KERNEL32.dll

### 进程管理（高置信）

**命中导入 API：**
- `KERNEL32.dll!CreateProcessW`
- `KERNEL32.dll!CreateToolhelp32Snapshot`
- `KERNEL32.dll!Process32FirstW`
- `KERNEL32.dll!Process32NextW`
- `KERNEL32.dll!TerminateProcess`

> 深挖：在 Ghidra 中定位 `CreateProcessW`，用 xrefs 找调用处、decompile 看伪代码；或用 REA CLI：`trace "C:\Program Files (x86)\ByteDance\douyin\douyin.exe" "CreateProcessW" --provider ghidra`

### 动态加载 / 延迟绑定（高置信）

**命中导入 API：**
- `KERNEL32.dll!GetProcAddress`
- `KERNEL32.dll!LoadLibraryExA`
- `KERNEL32.dll!LoadLibraryExW`
- `KERNEL32.dll!LoadLibraryW`
- `KERNEL32.dll!SetDllDirectoryW`

> 深挖：在 Ghidra 中定位 `GetProcAddress`，用 xrefs 找调用处、decompile 看伪代码；或用 REA CLI：`trace "C:\Program Files (x86)\ByteDance\douyin\douyin.exe" "GetProcAddress" --provider ghidra`

**相关库已导入（弱佐证）：** KERNEL32.dll

## 四、结论与下一步

### 总体判断（自动生成，仅供第一层参考）

- 有少量需关注项，结合程序用途判断即可。
- 检测到高熵节区，疑似压缩/加密/加壳，建议先脱壳/解包再分析。
- 重点模块：进程注入（高危），建议优先对这些模块做调用链深挖。

- 本报告基于**导入表 + 字符串**静态粗筛，属于第一层判断，**不等于运行时行为**；命中高危 API 只代表“具备该能力”，是否真正使用需结合反编译确认。
- 建议：从上表选择你关心的模块，再用 Ghidra `trace` / `decompile` / `xrefs` 对该模块对应 API 做调用链深挖。
- 静态推断条目请在最终结论中标注“静态推断”，勿直接判定为恶意。
