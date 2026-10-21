# 本地自主迭代记录（pe_module_scan.py 零依赖粗筛层）

> 本轮在 GitHub 账号暂停、无法推送的前提下，于本地持续迭代 `tools/pe_module_scan.py`。
> 所有改动以 `python tools\test_scan.py` 全绿为守门；合法系统样本不得判高危。

## 当前状态（2026-10-21）

- 回归断言 **107 项全绿**；13 个合法系统程序/库（notepad x86/x64、calc、taskmgr、
  regedit、explorer、kernel32/advapi32/user32/gdi32/wininet/bcrypt/ws2_32）全部落
  安全/低危区，无高危误报。
- 修复节区 Characteristics 偏移（b+36，误作 b+24），此前 RWX 可写可执行检测恒不命中。
- 对账守护：所有计分 API 归一化后都必须能归到某个报告模块，新增招数漏归类会被测试拦下。
- PyInstaller 单文件 `dist\pe_module_scan.exe`（约 8.1 MB）实测可运行，退出码正确。

## 已落地能力

### 高危招数库（精确 API 匹配，W/A 归一，DLL 仅弱佐证）
- 进程注入：CreateRemoteThread/Ex、NtCreateThreadEx、RtlCreateUserThread、QueueUserAPC、
  VirtualAllocEx/ProtectEx、Write/ReadProcessMemory、SetThreadContext；
  原生 NtWriteVirtualMemory/NtAllocateVirtualMemory、NtUnmapViewOfSection(进程空洞)
- 提权令牌：AdjustTokenPrivileges、CreateProcessAsUser、ImpersonateLoggedOnUser、
  SetThreadToken、NtLoadDriver(内核驱动)；DuplicateTokenEx 降为仅提示
- 内网通信：命名管道/邮件槽(CreateNamedPipe/ConnectNamedPipe/CreateMailslot)归类网络
- 键盘记录：SetWindowsHookEx、GetAsyncKeyState/GetKeyboardState、CallNextHookEx
- 录音/摄像头：waveInOpen、capCreateCaptureWindow（webcam/video capture 字符串）
- 截屏：BitBlt、PrintWindow
- 凭据窃取/反取证：CredEnumerate、LsaEnumerateLogonSessions、SamIConnect、ClearEventLog、
  EvtClearLog(现代日志)、浏览器 Login Data/Local State/Cookies、Firefox logins.json/key4.db
- 破坏安全软件：DeleteService/StopService、Set-MpPreference/netsh advfirewall/windefend 串
- 反调试：CheckRemoteDebuggerPresent、NtSetInformationThread、NtQueryInformationProcess
- 反虚拟机/反沙盒：VMware/VBox/QEMU/sandbox/VirusTotal/any.run 字符串
- 勒索特征：赎金信文件名、BTC 地址、删卷影副本(vssadmin/wmic shadowcopy/bcdedit)、.locked
- 数据外泄：FTP 上传、MAPI 邮件
- 下载执行：URLDownloadToFile、InternetOpenUrl、BITS(bitsadmin/backgroundcopy)；
  持久化：Run 键/计划任务/WMI/PowerShell -enc/userinit/win.ini
- 文件加密：CryptEncrypt/Decrypt；输入封锁 BlockInput

### PE 静态检测（纯标准库）
- 架构、SHA-256、数字签名目录、节区数/熵（≥7.0 高熵）
- 加壳三信号：节区名识别（UPX/VMProtect/Themida/ASPack）、入口点不落节区、RWX 节区
- 类型识别：.NET(CLR头)/Go build ID/Electron/NW.js/CEF/Node/Python/UPX
- 外联证据：URL/IPv4/域名，过滤微软帮助、回环/内网(10/192.168/172.16-31/169.254)、
  占位域名(example.com)、版本号 IP、源文件名

### CLI / 报告 / 工程
- `--report` Markdown、`--json`、`--quiet`、`--min-confidence high|medium|low`、`--version`
- 退出码：0 安全 / 1 可疑 / 2 高危 / 3 非PE；纯字符串高危模块在 high 过滤下保留
- 报告顶部高危速览、按命中模块给重点建议、自动 Ghidra 深挖命令；写入失败容错
- 高危组合联动判断：注入+外联/注入+持久化/凭据+外联 在小结给特征链提示（不改阈值）
- 报告含节区明细表（熵/X-R-W 权限，高熵与 RWX 标⚠️）；JSON 顶层带 network_evidence
- `--help` 含用法示例；截断/损坏 PE、不可读文件、不可写输出路径均友好报错不崩溃

### 第二轮：补缺点 + 超越原版（任务 #101–#108）
- **非 PE 格式引导**：识别 ELF/Mach-O/Java class/ZIP/gzip 魔数，给出原版 `inspect-*` 命令，不笼统报错。
- **外联归类**：公网 IP/域名列出并建议核查归属/信誉；回环/内网(10/192.168/172.16-31/169.254)
  归入 `private_ips` 参考、不计可疑。
- **PE 头补全**：EXE/DLL 标志、GUI/控制台子系统、编译时间戳（UTC），终端与报告同步。
- **批量分诊 `--batch`**：递归扫目录 exe/dll，按风险分降序排名，`--report` 落盘 Markdown 总表。
- **基线巡检 `--baseline`**：指纹库(sha256+分数)复扫，标注 新增/已替换/风险上升(≥10)/已见。
- 报告/汇总 Markdown 统一 UTF-8 BOM，记事本直开不乱码。

## 第三轮：代码复查与健壮性修复（2026-10-21，107 项断言）

通读 `pe_module_scan.py` 全量复查后修复：
- 批量子进程显式 `encoding="utf-8", errors="replace"`，避免中文 Windows 按 GBK
  解码子进程输出触发 UnicodeDecodeError 而误判失败。
- 批量单文件超时/读取失败单列“失败”、非PE单列，**绝不落入“安全”**（原先 else
  分支会把失败误标安全，掩盖问题）；抽 `_batch_tag()` 纯函数并加断言。
- 失败条目不写入基线指纹库，避免下次复扫把失败文件当成“已见/已替换”。
- MapiSendMail(mapi32.dll) 补入 network 的 DLL 限定，邮件外泄正确归入网络模块。
- 时间戳渲染由 `datetime.UTC`(Py3.11+) 改为 `datetime.timezone.utc`，兼容旧版本。

## 待用户 / 外部项（本机无法自动完成）
1. **真实样本动态校准**：dc 虚拟机已加固（删共享、clean-base 快照、剪贴板/拖拽关），
   需用户开机登录后在 VM 内投放 MalwareBazaar/EICAR 样本，回传行为报告以校准误报/漏报。
2. **GitHub 解封**：工单 4885170 等待人工回复，恢复前不推送、不反复登录。
3. **Ghidra 调用图深挖**：确认 API 是否真被调用、降低静态误报，属反编译阶段。

## 已知限制（不做，避免错误信息）
- 不解析 VS_VERSION_INFO 厂商/产品名（对齐假设错误）；不解析 PE 导出表（RVA 定位易错）。
- 静态"具备能力"≠运行时真使用，报告须标注静态推断。
