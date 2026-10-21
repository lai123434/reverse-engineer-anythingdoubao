# -*- coding: utf-8 -*-
"""
pe_module_scan.py — EXE 模块化拆分粗筛器（第一层，零第三方依赖）

用途：
    在启动重型 Ghidra 反编译之前，先用纯标准库解析 PE 导入表 + 提取字符串，
    把一个 EXE 内部的能力粗分成若干功能模块（网络/GUI/加密/文件/进程/注册表/
    服务/自启动/注入/反调试/提权/录音/截屏/剪贴板/键盘记录……），
    先给出模块清单和证据，供用户按需选择单个模块再用 Ghidra 深入，避免一次性
    吐出海量原始数据造成信息过载。

特点：
    - 仅用 Python 标准库，无需 pip 安装任何包，可直接 PyInstaller 打包单 EXE。
    - API 采用精确名匹配（忽略 W/A/Ex 后缀），DLL 仅作弱佐证，避免整库误报。
    - 只做静态推断，不运行目标程序；所有结论标注为“静态推断”。

用法：
    python pe_module_scan.py "C:\\path\\to\\app.exe"
    python pe_module_scan.py "app.exe" --report report.md --json result.json
"""

import argparse
import datetime
import hashlib
import json
import math
import os
import re
import struct
import subprocess
import sys

# 打包为单 EXE 后，中文控制台按 UTF-8 输出，避免乱码
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError, OSError):
        pass

# ----------------------------------------------------------------------------
# 模块规则表
#   apis    : 精确 API 名（大小写不敏感，自动忽略 W/A/Ex 后缀）
#   prefixes: API 名前缀（如 WinHttp、BCrypt）
#   dlls    : 相关 DLL 弱佐证（仅提示“该库已导入”，不计入命中数、不决定置信度）
#   strings : 强特征字符串（小写子串）
#   scope   : 仅当 API 来自这些 DLL 时才算命中（用于消除 send/recv 误中 SendMessage）
# ----------------------------------------------------------------------------
MODULES = [
    {
        "key": "network",
        "cn": "网络通信",
        "desc": "联网、收发数据、HTTP 请求、DNS 解析能力",
        "apis": ["wsastartup", "socket", "connect", "send", "recv",
                 "getaddrinfo", "gethostbyname", "internetopen",
                 "internetopenurl", "httpopenrequest", "httpsendrequest",
                 "internetreadfile", "dnsquery", "getpeername",
                 "ftpputfile", "ftpopen", "urldownloadtofile", "mapisendmail",
                 "createnamedpipe", "connectnamedpipe", "createmailslot"],
        "prefixes": ["winhttp"],
        "dlls": ["ws2_32.dll", "wininet.dll", "winhttp.dll", "dnsapi.dll",
                 "iphlpapi.dll", "mswsock.dll"],
        "scope": ["ws2_32.dll", "mswsock.dll", "wininet.dll", "winhttp.dll",
                  "dnsapi.dll", "mapi32.dll"],
        "strings": ["http://", "https://", "ftp://", "ws://", "wss://",
                    "smtp://", "mailto:", "mapi", "bitsadmin", "backgroundcopy"],
        "weight": 100,
    },
    {
        "key": "gui",
        "cn": "图形界面",
        "desc": "窗口、对话框、消息框等 UI 能力",
        "apis": ["createwindowex", "createwindow", "dialogboxparam",
                 "dialogbox", "messagebox", "registerclassex", "registerclass",
                 "createdialogparam", "showwindow", "defwindowproc",
                 "getmessage", "dispatchmessage"],
        "prefixes": [],
        "dlls": ["user32.dll", "gdi32.dll", "comctl32.dll", "dwmapi.dll"],
        "scope": [],
        "strings": [],
        "weight": 30,
    },
    {
        "key": "crypto",
        "cn": "加密 / 编码",
        "desc": "对称/非对称加密、哈希、Base64 等编码能力",
        "apis": ["cryptacquirecontext", "cryptencrypt", "cryptdecrypt",
                 "crypthashdata", "cryptcreatehash", "bcryptopenalgorithmprovider",
                 "bcryptencrypt", "bcryptdecrypt", "bcrypthashdata"],
        "prefixes": [],
        "dlls": ["bcrypt.dll", "crypt32.dll", "ncrypt.dll"],
        "scope": [],
        "strings": ["aes-128", "aes-256", "aes128", "aes256", "aes-gcm", "rsa",
                    "sha256", "sha-256", "sha1", "md5", "base64", "chacha20",
                    "rc4", "des", "blowfish", "dpapi"],
        "weight": 60,
    },
    {
        "key": "fileio",
        "cn": "文件读写",
        "desc": "创建/读取/写入/删除/复制文件",
        "apis": ["createfile", "readfile", "writefile", "deletefile",
                 "copyfile", "movefile", "shfileoperation", "findfirstfile",
                 "gettemppath"],
        "prefixes": [],
        "dlls": ["kernel32.dll", "shlwapi.dll", "shell32.dll"],
        "scope": [],
        "strings": ["\\appdata", "\\temp", "\\downloads", ".ini", "\\documents",
                    "\\desktop", "\\pictures", "\\videos"],
        "weight": 20,
    },
    {
        "key": "process",
        "cn": "进程管理",
        "desc": "创建、枚举、结束其他进程",
        "apis": ["openprocess", "createtoolhelp32snapshot", "process32first",
                 "process32next", "enumprocesses", "createprocess",
                 "createprocessasuser", "terminateprocess", "openprocesstoken",
                 "winexec", "shellexecute", "blockinput"],
        "prefixes": [],
        "dlls": ["psapi.dll", "toolhelp.dll"],
        "scope": [],
        "strings": [],
        "weight": 50,
    },
    {
        "key": "registry",
        "cn": "注册表读写",
        "desc": "打开/创建/读写/删除注册表键值",
        "apis": ["regopenkey", "regcreatekey", "regsetvalue", "regqueryvalue",
                 "regdeletevalue", "regdeletekey", "regclosekey", "regenumkey"],
        "prefixes": [],
        "dlls": ["advapi32.dll"],
        "scope": [],
        "strings": ["hkey_local_machine", "hkey_current_user", "software\\"],
        "weight": 40,
    },
    {
        "key": "service",
        "cn": "服务管理",
        "desc": "创建/配置/启动/删除 Windows 服务",
        "apis": ["openscmanager", "createservice", "openservice",
                 "changeserviceconfig", "startservice", "deleteservice",
                 "stopservice", "queryservicestatus"],
        "prefixes": [],
        "dlls": ["advapi32.dll"],
        "scope": [],
        "strings": ["services\\", "set-mppreference", "advfirewall",
                    "sc stop windefend", "windefend", "disableantispyware"],
        "weight": 55,
    },
    {
        "key": "dynamicload",
        "cn": "动态加载 / 延迟绑定",
        "desc": "运行时 LoadLibrary + GetProcAddress 取函数，可规避静态导入表（常见于恶意程序）",
        "apis": ["loadlibrary", "loadlibraryex", "getprocaddress", "setdlldirectory"],
        "prefixes": [],
        "dlls": ["kernel32.dll"],
        "scope": [],
        "strings": [],
        "weight": 45,
    },
    {
        "key": "persistence",
        "cn": "自启动 / 持久化",
        "desc": "写入 Run 键、启动目录、计划任务等驻留手段（需命中驻留路径字符串）",
        "apis": ["regsetvalue"],
        "prefixes": [],
        "dlls": [],
        "scope": [],
        "strings": ["currentversion\\run", "currentversion\\runonce",
                    "wow6432node\\run", "\\startup", "schtasks", "\\autostart",
                    "schtasks /create", "task scheduler", "\\tasks\\",
                    "winlogon", "appinit_dlls", "boot execute",
                    "wmic", "win32_process", "powershell -enc", "encodedcommand",
                    "userinit", "system.ini", "win.ini", "shell=",
                    "sethc.exe", "utilman.exe", "utilman",
                    "image file execution options", "ifeo"],
        "weight": 80,
    },
    {
        "key": "injection",
        "cn": "进程注入（高危）",
        "desc": "向其他进程分配内存并写入代码、远程建线程",
        "apis": ["createremotethread", "virtualallocex", "writeprocessmemory",
                 "readprocessmemory", "ntcreatethreadex", "rtlcreateuserthread",
                 "queueuserapc", "virtualprotectex", "ntwritevirtualmemory",
                 "ntunmapviewofsection", "ntallocatevirtualmemory",
                 "setthreadcontext", "ntqueueapcthread", "createremotethreadex"],
        "prefixes": [],
        "dlls": ["kernel32.dll"],
        "scope": [],
        "strings": [],
        "weight": 100,
    },
    {
        "key": "anti_debug",
        "cn": "反调试",
        "desc": "检测调试器、干扰逆向分析（IsDebuggerPresent 为运行库常见项）",
        "apis": ["checkremotedebuggerpresent", "ntsetinformationthread",
                 "ntqueryinformationprocess", "debugactiveprocess",
                 "setthreadcontext", "isdebuggerpresent"],
        "prefixes": [],
        "dlls": ["ntdll.dll"],
        "scope": [],
        "strings": ["ollydbg", "x64dbg", "windbg", "ida pro", "ida64",
                    "ghidra", "dnspy", "frida", "debugger",
                    "softice", "scylla", "peid"],
        "weight": 90,
    },
    {
        "key": "privilege",
        "cn": "提权 / 令牌操作",
        "desc": "打开进程令牌、调整特权（如 SeDebugPrivilege）",
        "apis": ["adjusttokenprivileges", "lookupprivilegevalue",
                 "impersonateself", "impersonateloggedonuser", "setthreadtoken",
                 "settokeninformation", "openprocesstoken",
                 "duplicatetokenex", "duplicatetoken",
                 "ntloaddriver", "loaddriver", "createprocessasuser"],
        "prefixes": [],
        "dlls": ["advapi32.dll"],
        "scope": [],
        "strings": ["sedebugprivilege"],
        "weight": 95,
    },
    {
        "key": "audio",
        "cn": "录音 / 音视频采集",
        "desc": "麦克风录音、摄像头采集",
        "apis": ["waveinopen", "waveinstart", "mcisendstring",
                 "capcreatecapturewindow"],
        "prefixes": [],
        "dlls": ["winmm.dll", "avrt.dll", "avicap32.dll"],
        "scope": [],
        "strings": [".wav", "microphone", "record audio",
                    "webcam", "video capture", "avicap"],
        "weight": 85,
    },
    {
        "key": "screenshot",
        "cn": "屏幕截取",
        "desc": "抓取桌面窗口画面",
        "apis": ["bitblt", "printwindow"],
        "prefixes": [],
        "dlls": ["gdi32.dll"],
        "scope": [],
        "strings": [".bmp", "screenshot", "screen record",
                    "screen capture", "record screen"],
        "weight": 70,
    },
    {
        "key": "clipboard",
        "cn": "剪贴板读取",
        "desc": "读取/写入系统剪贴板内容",
        "apis": ["getclipboarddata", "setclipboarddata", "emptyclipboard",
                 "openclipboard"],
        "prefixes": [],
        "dlls": ["user32.dll"],
        "scope": [],
        "strings": ["clipboard"],
        "weight": 65,
    },
    {
        "key": "keylog",
        "cn": "键盘记录（高危）",
        "desc": "全局钩子、轮询按键状态",
        "apis": ["setwindowshookex", "getasynckeystate", "getkeystate",
                 "getkeyboardstate", "mapvirtualkey",
                 "callnexthookex", "unhookwindowshookex"],
        "prefixes": [],
        "dlls": ["user32.dll"],
        "scope": [],
        "strings": ["keylog", "keystroke"],
        "weight": 100,
    },
    {
        "key": "creds",
        "cn": "凭据窃取 / 反取证（高危）",
        "desc": "枚举保存凭据、访问 LSA/SAM、清除事件日志销毁痕迹",
        "apis": ["credenumerate", "lsaenumeratelogonsessions", "samiconnect",
                 "cleareventlog", "evtclearlog"],
        "prefixes": [],
        "dlls": ["advapi32.dll", "sechost.dll", "wevtapi.dll"],
        "scope": [],
        "strings": ["lsass", "sam database", "eventlog", "security log",
                    "login data", "local state", "web data", "cookies",
                    "logins.json", "key4.db", "history", "bookmarks",
                    "chrome user data", "browser password"],
        "weight": 95,
    },
    {
        "key": "anti_vm",
        "cn": "反虚拟机 / 反沙盒",
        "desc": "检测 VMware/VBox/QEMU/沙盒环境，避免在分析环境中真正运行",
        "apis": [],
        "prefixes": [],
        "dlls": [],
        "scope": [],
        "strings": ["vmware", "virtualbox", "vboxservice", "vboxmouse", "vmtoolsd",
                    "qemu", "xen", "sandbox", "virustotal", "any.run", "wireshark",
                    "virtual machine"],
        "weight": 70,
    },
    {
        "key": "ransom",
        "cn": "勒索特征（高危）",
        "desc": "勒索信文件名、加密后扩展名、赎金说明等典型勒索软件痕迹",
        "apis": [],
        "prefixes": [],
        "dlls": [],
        "scope": [],
        "strings": ["readme-decrypt", "decrypt-instructions", "your files are encrypted",
                    "your files have been encrypted", "ransom note", "btc wallet",
                    "bitcoin address", "locked files", "payment required",
                    ".locked", ".encrypted", ".enc", "how to decrypt",
                    "decrypt your files", "restoration fee",
                    "vssadmin delete shadows", "delete shadows", "shadowcopy delete",
                    "bcdedit /set", "recoveryenabled no", "wbadmin delete catalog"],
        "weight": 95,
    },
]

# 高危优先模块：在清单/明细中置顶并标注"优先深挖"
HIGH_PRIORITY_KEYS = {"injection", "keylog", "creds", "privilege",
                      "audio", "anti_vm", "ransom"}


def _keep_module(m, min_api):
    """置信过滤：API 数达标保留；纯字符串高危模块命中字符串也保留。"""
    return m["n_api"] >= min_api or (
        m["key"] in HIGH_PRIORITY_KEYS and m["n_str"] > 0)

# 高危特征库：api 精确名(归一化) -> (分值, 中文说明, 类别, 是否运行库常见)
# common=True 的项目只作提示、不计入主分，避免运行库普遍导入造成误报。
HIGH_RISK = {
    "createremotethread": (25, "向远程进程创建线程（代码注入经典手法）", "进程注入", False),
    "createremotethreadex": (25, "向远程进程创建线程（代码注入）", "进程注入", False),
    "virtualallocex": (10, "在远程进程分配内存", "进程注入", False),
    "writeprocessmemory": (15, "向远程进程写入内存（配合注入）", "进程注入", False),
    "readprocessmemory": (8, "读取远程进程内存（窃密/注入辅助）", "进程注入", False),
    "ntwritevirtualmemory": (13, "原生写远程进程内存（配合注入）", "进程注入", False),
    "ntallocatevirtualmemory": (10, "原生在远程进程分配内存（注入）", "进程注入", False),
    "ntunmapviewofsection": (12, "卸载远程进程原镜像（进程空洞 Hollowing）", "进程注入", False),
    "ntcreatethreadex": (25, "原生远程建线程注入", "进程注入", False),
    "rtlcreateuserthread": (20, "远程用户态线程注入", "进程注入", False),
    "queueuserapc": (12, "APC 异步过程调用注入", "进程注入", False),
    "checkremotedebuggerpresent": (8, "远程检测调试器", "反调试", False),
    "ntsetinformationthread": (10, "可用于隐藏调试状态/线程", "反调试", False),
    "adjusttokenprivileges": (15, "调整令牌特权（可用于提权）", "提权", False),
    "lookupprivilegevalue": (5, "查询特权（常配合提权）", "提权", False),
    "setwindowshookex": (15, "安装全局钩子（键盘记录常用）", "键盘记录", False),
    "getasynckeystate": (12, "轮询按键状态（键盘记录）", "键盘记录", False),
    "waveinopen": (12, "打开录音设备", "录音", False),
    "capcreatecapturewindow": (12, "创建视频采集窗口（摄像头）", "音视频采集", False),
    "bitblt": (5, "位图拷贝（可用于截屏）", "截屏", False),
    "printwindow": (5, "抓取窗口画面", "截屏", False),
    "virtualprotectex": (8, "远程进程修改内存保护（配合注入）", "进程注入", False),
    "ntqueueapcthread": (12, "APC 队列注入目标线程", "进程注入", False),
    "urldownloadtofilew": (15, "从 URL 下载文件（常配合下载执行）", "下载执行", False),
    "urldownloadtofilea": (15, "从 URL 下载文件", "下载执行", False),
    "createservicew": (12, "创建系统服务（持久化/提权）", "持久化", False),
    "createservicea": (12, "创建系统服务", "持久化", False),
    "cryptencrypt": (15, "加密数据（勒索软件加密文件特征）", "文件加密", False),
    "blockinput": (10, "封锁鼠标键盘输入（干扰/勒索）", "输入封锁", False),
    "winexec": (6, "启动外部程序", "执行", False),
    "shellexecute": (6, "外壳启动外部程序", "执行", False),
    "cryptdecrypt": (12, "解密数据（配合加密/勒索或还原载荷）", "文件加密", False),
    "internetopenurl": (10, "打开 URL 下载/联网（WinINet）", "下载执行", False),
    "internetopen": (6, "建立 WinINet 会话（外联）", "网络外联", False),
    "ftpputfile": (8, "FTP 上传文件（数据外泄）", "数据外泄", False),
    "mapisendmail": (8, "经 MAPI 发送邮件（可用于数据外泄）", "数据外泄", False),
    "createprocessasuser": (10, "以其他用户身份创建进程（提权/横向移动）", "提权", False),
    "impersonateloggedonuser": (10, "模拟已登录用户令牌（会话劫持/提权）", "提权", False),
    "setthreadtoken": (8, "给线程挂上模拟令牌（会话劫持）", "提权", False),
    "ntloaddriver": (12, "原生加载内核驱动（内核提权/rootkit）", "提权", False),
    "loaddriver": (10, "加载驱动（内核提权/rootkit）", "提权", False),
    "duplicatetokenex": (0, "复制令牌（管理工具常见，需确认是否模拟提权）", "提权", True),
    "ntqueryinformationprocess": (8, "查询进程信息（可用于反调试/枚举）", "反调试", False),
    "setthreadcontext": (8, "修改线程上下文（注入/劫持执行流辅助）", "进程注入", False),
    "credenumerate": (12, "枚举系统保存的凭据（凭据窃取）", "凭据窃取", False),
    "lsaenumeratelogonsessions": (10, "枚举 LSA 登录会话（凭据窃取）", "凭据窃取", False),
    "samiconnect": (10, "连接 SAM 数据库（账户/凭据窃取）", "凭据窃取", False),
    "cleareventlog": (12, "清除事件日志（销毁痕迹）", "反取证", False),
    "evtclearlog": (12, "清除现代 Windows 事件日志（销毁痕迹）", "反取证", False),
    "deleteservice": (10, "删除服务（常用来停安全软件）", "破坏安全软件", False),
    "stopservice": (6, "停止服务（常用来停安全软件）", "破坏安全软件", False),
    "setdlldirectory": (6, "设置 DLL 搜索目录（DLL 劫持/侧载）", "DLL劫持", False),
    "getkeyboardstate": (8, "读取整个键盘状态（键盘记录补充）", "键盘记录", False),
    # —— 运行库常见，仅提示不计分 ——
    "isdebuggerpresent": (0, "检测调试器（运行库常见，需确认是否主动调用）", "反调试", True),
    "openprocesstoken": (0, "打开进程令牌（运行库常见）", "提权", True),
    "openclipboard": (0, "打开剪贴板（GUI 程序常见）", "剪贴板", True),
}

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.I)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
# 视为良性帮助/命名空间链接，不计入可疑外联
BENIGN_HOST = ("go.microsoft.com", "schemas.microsoft.com", "microsoft.com",
               "w3.org", "www.w3.org", "schemas.xmlsoap.org", "openxmlformats.org",
               "example.com", "example.org", "example.net", "localhost",
               "test.com", "sample.com", "domain.com", "yourdomain.com")
# 仅保留这些常见顶级域，过滤源文件名/命名空间/版本号噪声
KNOWN_TLD = ("com", "net", "org", "ru", "io", "cn", "xyz", "top", "info", "biz",
             "dev", "app", "co", "me", "cc", "tv", "ai", "online", "site", "shop",
             "store", "club", "pro", "uk", "de", "jp", "hk", "tw", "link", "live")
# PE 段名 / 资源噪声，不作为字符串证据
NOISE_SEGMENTS = {".text", ".rdata", ".data", ".bss", ".idata", ".didat",
                  ".edata", ".rsrc", ".reloc", ".pdata", ".tls", ".debug"}


def _norm_api(name):
    """归一化 API 名：小写并去掉结尾单个 W/A 宽/窄字符后缀（不动 Ex）。"""
    n = name.lower()
    if len(n) > 3 and n[-1] in ("w", "a"):
        n = n[:-1]
    return n


# ----------------------------------------------------------------------------
# PE 解析（纯标准库）
# ----------------------------------------------------------------------------
def _cstr(data, off):
    if off is None or off < 0 or off >= len(data):
        return ""
    end = data.find(b"\0", off)
    if end == -1:
        end = len(data)
    return data[off:end].decode("ascii", "ignore")


def parse_pe_imports(data):
    """返回 (imports[(dll,api)], is64, sections)；非 PE/截断损坏返回 (None, None, None)。"""
    if data[:2] != b"MZ" or len(data) < 0x40:
        return None, None, None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return None, None, None

    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    is64 = magic == 0x20b

    dd_off = opt + (112 if is64 else 96)
    import_rva = struct.unpack_from("<I", data, dd_off + 8)[0]

    sec_off = opt + opt_size
    sections = []
    for i in range(num_sections):
        b = sec_off + i * 40
        if b + 40 > len(data):
            break
        va = struct.unpack_from("<I", data, b + 12)[0]
        vsize = struct.unpack_from("<I", data, b + 8)[0]
        rawsize = struct.unpack_from("<I", data, b + 16)[0]
        rawptr = struct.unpack_from("<I", data, b + 20)[0]
        sections.append((va, vsize, rawptr, rawsize))

    def rva2off(rva):
        for va, vsize, rawptr, rawsize in sections:
            span = max(vsize, rawsize)
            if span and va <= rva < va + span:
                return rawptr + (rva - va)
        return None

    imports = []
    if import_rva:
        d = rva2off(import_rva)
        while d and d + 20 <= len(data):
            oft, _ts, _fwd, name_rva, ft = struct.unpack_from("<IIIII", data, d)
            if name_rva == 0 and oft == 0 and ft == 0:
                break
            dll = _cstr(data, rva2off(name_rva)) or "?"
            thunk = oft if oft else ft
            to = rva2off(thunk)
            while to and to < len(data):
                if is64:
                    val = struct.unpack_from("<Q", data, to)[0]
                    to += 8
                    if val == 0:
                        break
                    if val & (1 << 63):
                        api = f"#ord{val & 0xFFFF}"
                    else:
                        h = rva2off(val & 0x7FFFFFFF)
                        api = _cstr(data, h + 2) if h is not None else "?"
                else:
                    val = struct.unpack_from("<I", data, to)[0]
                    to += 4
                    if val == 0:
                        break
                    if val & 0x80000000:
                        api = f"#ord{val & 0xFFFF}"
                    else:
                        h = rva2off(val)
                        api = _cstr(data, h + 2) if h is not None else "?"
                if api:
                    imports.append((dll, api))
            d += 20
    return imports, is64, sections


def _perm_str(chars):
    """解码节区 Characteristics 位为 X/R/W 字符串。"""
    return ("X" if chars & 0x20000000 else "-") + \
           ("R" if chars & 0x40000000 else "-") + \
           ("W" if chars & 0x80000000 else "-")


def _shannon(buf):
    """计算字节序列的香农熵（0-8），用于识别压缩/加密/加壳节区。"""
    if not buf:
        return 0.0
    freq = [0] * 256
    for b in buf:
        freq[b] += 1
    n = len(buf)
    h = 0.0
    for c in freq:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def compute_pe_info(data):
    """节区熵/高熵(加壳)提示、数字签名、入口点；非 PE/截断返回 None。"""
    if data[:2] != b"MZ" or len(data) < 0x40:
        return None
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if e + 24 > len(data) or data[e:e + 4] != b"PE\0\0":
        return None
    coff = e + 4
    num_sec = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    is64 = magic == 0x20b
    entrypoint = struct.unpack_from("<I", data, opt + 16)[0]
    # COFF: coff+4 TimeDateStamp(4)，coff+18 Characteristics(2)；0x2000 = IMAGE_FILE_DLL
    timestamp = struct.unpack_from("<I", data, coff + 4)[0]
    characteristics = struct.unpack_from("<H", data, coff + 18)[0]
    is_dll = bool(characteristics & 0x2000)
    # Subsystem：PE32+ 在 opt+68，PE32 在 opt+44；2=GUI 图形界面，3=控制台 CUI
    subsystem = struct.unpack_from("<H", data, opt + (68 if is64 else 44))[0]

    dd = opt + (112 if is64 else 96)
    # 安全目录（数字签名）为数据目录第 5 项（index 4）
    sec_off = struct.unpack_from("<I", data, dd + 32)[0]
    sec_size = struct.unpack_from("<I", data, dd + 36)[0]
    signed = sec_off != 0 and sec_size > 0

    # 常见加壳器/打包器节区名 -> 名称（小写匹配）
    PACKER_SECTION = {
        "upx0": "UPX", "upx1": "UPX", ".upx0": "UPX", ".upx1": "UPX",
        ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
        ".themida": "Themida", ".winlic": "Themida",
        ".aspack": "ASPack", ".adata": "ASPack",
        ".nsp0": "NSIS", ".nsp1": "NSIS",
        ".petite": "Petite", ".pz": "PZip",
    }

    so = opt + opt_size
    secs, high, packers, rwx = [], [], set(), []
    for i in range(num_sec):
        b = so + i * 40
        if b + 40 > len(data):
            break
        name = data[b:b + 8].split(b"\0")[0].decode("ascii", "ignore")
        vsize = struct.unpack_from("<I", data, b + 8)[0]
        va = struct.unpack_from("<I", data, b + 12)[0]
        rawsize = struct.unpack_from("<I", data, b + 16)[0]
        rawptr = struct.unpack_from("<I", data, b + 20)[0]
        chars = struct.unpack_from("<I", data, b + 36)[0]
        chunk = data[rawptr:rawptr + rawsize] if rawptr + rawsize <= len(data) else b""
        ent = _shannon(chunk)
        # RWX：同时可执行(0x20000000)且可写(0x80000000)，正常代码节不应可写，注入/加壳可疑
        if (chars & 0x20000000) and (chars & 0x80000000):
            rwx.append(name or f"#{i}")
        secs.append({"name": name, "vsize": vsize, "va": va,
                     "rawsize": rawsize, "entropy": round(ent, 2),
                     "chars": chars})
        p = PACKER_SECTION.get(name.lower())
        if p:
            packers.add(p)
        if ent >= 7.0 and rawsize > 0:
            high.append((name, round(ent, 2)))

    # 入口点 RVA 是否落在某节区；不落任何节区通常意味着加壳/重定向
    ep_outside = True
    for s in secs:
        span = max(s["vsize"], s["rawsize"])
        if s["va"] <= entrypoint < s["va"] + span:
            ep_outside = False
            break

    return {"is64": is64, "entrypoint": entrypoint, "signed": signed,
            "is_dll": is_dll, "timestamp": timestamp, "subsystem": subsystem,
            "sections": secs, "high_entropy": high,
            "packer": sorted(packers), "ep_outside": ep_outside,
            "rwx_sections": rwx}


def extract_strings(data, minlen=4, limit=4000):
    """提取 ASCII 与 UTF-16LE 可打印字符串，去重保序，过滤段名/XML 噪声，限量。"""
    out, seen = [], set()

    def clean(s):
        s = s.strip()
        if len(s) < minlen:
            return None
        low = s.lower()
        if low in NOISE_SEGMENTS or low.startswith(".") and low.split("$")[0] in NOISE_SEGMENTS:
            return None
        if "<" in s and ">" in s:  # XML / 资源标签
            return None
        return s

    def push(s):
        c = clean(s)
        if c and c not in seen:
            seen.add(c)
            out.append(c)

    # ASCII
    cur = []
    for b in data:
        if 0x20 <= b < 0x7F:
            cur.append(chr(b))
        else:
            if len(cur) >= minlen:
                push("".join(cur))
            cur = []
    if len(cur) >= minlen:
        push("".join(cur))

    # UTF-16LE
    cur = []
    i, n = 0, len(data) - 1
    while i < n:
        lo, hi = data[i], data[i + 1]
        if hi == 0 and 0x20 <= lo < 0x7F:
            cur.append(chr(lo))
            i += 2
        else:
            if len(cur) >= minlen:
                push("".join(cur))
            cur = []
            i += 2
    if len(cur) >= minlen:
        push("".join(cur))

    return out[:limit]


def extract_network_evidence(strings):
    """从字符串提取 URL / IPv4 / 域名，过滤良性帮助链接与回环地址。"""
    urls, ips, domains, private_ips = [], [], [], []
    seen_u, seen_i, seen_d, seen_p = set(), set(), set(), set()
    for s in strings:
        low = s.lower()
        for u in URL_RE.findall(s):
            host = re.sub(r"^https?://", "", u).split("/")[0].split(":")[0]
            if any(b in host for b in BENIGN_HOST):
                continue
            if u not in seen_u:
                seen_u.add(u)
                urls.append(u)
        for ip in IP_RE.findall(s):
            octs = ip.split(".")
            if any(int(x) > 255 for x in octs):
                continue
            # 回环/本机/广播 → 内网参考，不算可疑外联
            if octs[0] in ("127", "0", "255") or ip in ("0.0.0.0", "255.255.255.255"):
                if ip not in seen_p:
                    seen_p.add(ip)
                    private_ips.append(ip)
                continue
            # 内网/保留地址：10/8、192.168/16、172.16-31/12、169.254 APIPA → 内网参考
            is_private = (octs[0] == "10"
                          or (octs[0] == "192" and octs[1] == "168")
                          or (octs[0] == "172" and 16 <= int(octs[1]) <= 31)
                          or (octs[0] == "169" and octs[1] == "254"))
            if is_private:
                if ip not in seen_p:
                    seen_p.add(ip)
                    private_ips.append(ip)
                continue
            # 跳过以 .0 结尾的版本号/SDK 编号（如 5.1.0.0、6.0.0.0、10.0.0.0）
            if octs[3] == "0":
                continue
            if ip not in seen_i:
                seen_i.add(ip)
                ips.append(ip)
        for d in DOMAIN_RE.findall(s):
            dl = d.lower()
            if any(b in dl for b in BENIGN_HOST):
                continue
            if dl.endswith((".dll", ".exe", ".txt", ".dat", ".log", ".ini",
                            ".drv", ".cpp", ".pdb", ".h", ".cs", ".obj", ".res")):
                continue
            tld = dl.rsplit(".", 1)[-1]
            if tld not in KNOWN_TLD:
                continue
            if dl not in seen_d:
                seen_d.add(dl)
                domains.append(dl)
    return {"urls": urls, "ips": ips, "domains": domains, "private_ips": private_ips}


def detect_runtime(data, strings):
    """检测 .NET 托管 / Go / UPX 加壳 / Electron-Node 运行时。"""
    result = {"dotnet": False, "go": None, "packer": None, "runtime": None, "hints": []}
    low = [s.lower() for s in strings]

    # .NET：COM 描述符目录（data directory index 14）非零
    if data[:2] == b"MZ" and len(data) > 0x40:
        e = struct.unpack_from("<I", data, 0x3C)[0]
        if e + 24 <= len(data) and data[e:e + 4] == b"PE\0\0":
            coff = e + 4
            opt_size = struct.unpack_from("<H", data, coff + 16)[0]
            opt = coff + 20
            magic = struct.unpack_from("<H", data, opt)[0]
            dd = opt + (112 if magic == 0x20b else 96)
            clr_rva = struct.unpack_from("<I", data, dd + 14 * 8)[0]
            if clr_rva:
                result["dotnet"] = True
                result["hints"].append(".NET 托管程序：建议改用 inspect-managed-artifact / 反编译 CIL")

    # Go
    for s in low:
        if "go build id" in s:
            result["go"] = s.strip()[:60]
            result["hints"].append("Go 二进制：建议用 inspect-go-binary 查看模块依赖")
            break
    # UPX 加壳
    if any("upx0" in s or "upx1" in s or "upx!" in s for s in low):
        result["packer"] = "UPX"
        result["hints"].append("疑似 UPX 加壳：先脱壳再分析，否则导入表/字符串严重缺失")
    # Electron / NW.js / CEF / Node / Python
    if any("electron" in s or "nwjs" in s for s in low):
        result["runtime"] = "Electron/NW.js"
        result["hints"].append("Electron/NW.js 应用：建议用 analyze-javascript-application 解包分析")
    elif any("chrome_cef" in s or "cefsharp" in s or "libcef" in s for s in low):
        result["runtime"] = "CEF"
    elif any("node.js" in s or "v8::" in s for s in low):
        result["runtime"] = "Node"
    elif any(s.startswith("python3") or "python.dll" in s or "pydata" in s for s in low):
        result["runtime"] = "Python(打包)"
    return result


def detect_artifact_format(data):
    """按魔数识别非 PE 格式，返回 (类型名, 原版 rea-agents 引导命令)；未知返回 (None, None)。"""
    head = data[:16]
    if head[:4] == b"\x7fELF":
        return "ELF (Linux/Unix 可执行)", "inspect-artifact"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                    b"\xfe\xed\xfa\xed", b"\xed\xfa\xed\xfe"):
        return "Mach-O (macOS/iOS)", "inspect-macho"
    if head[:4] == b"\xca\xfe\xba\xbe":
        return "Java .class 字节码", "inspect-artifact"
    if head[:4] == b"PK\x03\x04":
        return "ZIP / APK / JAR 归档", "inspect-artifact（APK 走 JADX/Android 流程）"
    if head[:3] == b"\x1f\x8b\x08":
        return "gzip 压缩流", "inspect-artifact"
    return None, None


# ----------------------------------------------------------------------------
# 归类 + 打分
# ----------------------------------------------------------------------------
def _api_matches(api_norm, m):
    # 规则名同样归一化（去掉 W/A/Ex 后缀）后再精确比较
    if any(api_norm == _norm_api(a) for a in m["apis"]):
        return True
    return any(api_norm.startswith(p) for p in m.get("prefixes", []))


# 运行库常见 API：单独标注，不计入模块命中与置信
COMMON_API = {k for k, (_p, _e, _c, is_common) in HIGH_RISK.items() if is_common}


def classify(imports, strings):
    lower_strings = [s.lower() for s in strings]
    # 所有已知 API 归一化名：字符串若本身就是 API 名（如 openclipboard），视为噪声跳过
    api_names = set(HIGH_RISK.keys())
    for _m in MODULES:
        for _a in _m["apis"]:
            api_names.add(_norm_api(_a))
    modules = []

    for m in MODULES:
        api_hits, str_hits, dll_hits, common_hits = [], [], [], []
        scope = [x.lower() for x in m.get("scope", [])]

        for dll, api in imports:
            dl, an = dll.lower(), _norm_api(api)
            # DLL 仅作弱佐证
            if any(k in dl for k in m["dlls"]):
                dll_hits.append(dll)
            # 运行库常见项单独记录，不撑起模块
            if an in COMMON_API:
                common_hits.append(f"{dll}!{api}")
                continue
            # 精确 API 命中（可选 DLL 范围限定）
            if _api_matches(an, m):
                if scope and dl not in scope:
                    continue
                api_hits.append(f"{dll}!{api}")

        for s in lower_strings:
            if any(b in s for b in BENIGN_HOST):
                continue  # 过滤微软帮助链接等良性字符串
            if _norm_api(s) in api_names:
                continue  # 字符串本身就是 API 名，非证据
            if any(k in s for k in m["strings"]):
                str_hits.append(s)

        api_hits = list(dict.fromkeys(api_hits))
        str_hits = list(dict.fromkeys(str_hits))
        dll_hits = list(dict.fromkeys(dll_hits))
        common_hits = list(dict.fromkeys(common_hits))

        n_api, n_str = len(api_hits), len(str_hits)
        # 持久化必须命中驻留路径字符串，单凭 RegSetValueEx 不算
        if m["key"] == "persistence" and n_str == 0:
            continue
        # 只有真实 API 命中或强字符串才让模块出现；dll/common 仅作补充展示
        if n_api == 0 and n_str == 0:
            continue

        if n_api >= 2:
            conf = "高"
        elif n_api == 1:
            conf = "中"
        else:
            conf = "低（仅弱字符串）"

        modules.append({
            "key": m["key"],
            "cn": m["cn"],
            "desc": m["desc"],
            "weight": m["weight"],
            "confidence": conf,
            "api_hits": api_hits,
            "str_hits": str_hits,
            "dll_hits": dll_hits,
            "common_hits": common_hits,
            "n_api": n_api,
            "n_str": n_str,
        })

    modules.sort(key=lambda x: (x["n_api"] * 3 + x["n_str"], x["weight"]), reverse=True)
    return modules


def score(imports, trusted=False):
    risk_norm = {_norm_api(k): v for k, v in HIGH_RISK.items()}
    findings, common, total = [], [], 0
    seen = set()
    for dll, api in imports:
        an = _norm_api(api)
        for key, (pts, explain, cat, is_common) in risk_norm.items():
            if an == key and key not in seen:
                seen.add(key)
                row = {"api": f"{dll}!{api}", "points": pts,
                       "category": cat, "explain": explain, "common": is_common}
                if is_common:
                    common.append(row)
                else:
                    total += pts
                    findings.append(row)
    total = min(total, 100)
    # 可信样本（已签名或位于系统目录；系统文件签名多在 catalog 而非 exe 安全目录）：
    # 系统库普遍导出高危 API，做 0.35 减免，避免满分误报；命中 API 仍在报告列出供人工判断
    if trusted and total > 0:
        total = round(total * 0.35)
    if total >= 70:
        level = "高危"
    elif total >= 40:
        level = "可疑（需人工复核）"
    elif total >= 20:
        level = "低危（需关注）"
    else:
        level = "安全 / 低关注"
    findings.sort(key=lambda x: x["points"], reverse=True)
    return total, level, findings, common


# ----------------------------------------------------------------------------
# 报告
# ----------------------------------------------------------------------------
def build_report(path, data, imports, is64, modules, total, level, findings, common, pe_info=None, runtime=None, net_ev=None):
    size = len(data)
    sha = hashlib.sha256(data).hexdigest()
    fname = os.path.basename(path)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = []
    lines.append(f"# EXE 模块化分析报告：{fname}\n")
    lines.append(f"> 生成时间：{now}　|　分析方式：静态粗筛（未运行程序）\n")
    hi = [m for m in modules
          if m["key"] in HIGH_PRIORITY_KEYS and (m["n_api"] + m["n_str"]) > 0]
    if hi:
        lines.append("## ⚠️ 高危速览（优先深挖）\n")
        for m in hi:
            lines.append(f"- **{m['cn']}**（API {m['n_api']} / 字符串 {m['n_str']}）— {m['desc']}")
        lines.append("")
    lines.append("## 一、样本信息\n")
    lines.append("| 项 | 值 |")
    lines.append("|---|---|")
    lines.append(f"| 文件 | {fname} |")
    lines.append(f"| 大小 | {size:,} 字节 |")
    lines.append(f"| 架构 | {'x64 (PE32+)' if is64 else 'x86 (PE32)'} |")
    if pe_info:
        lines.append(f"| 类型 | {'DLL 动态链接库' if pe_info.get('is_dll') else 'EXE 可执行文件'} |")
        _sub = {2: "GUI 图形界面", 3: "控制台 CUI"}.get(pe_info.get("subsystem"))
        if _sub:
            lines.append(f"| 界面子系统 | {_sub} |")
        _ts = pe_info.get("timestamp") or 0
        if 86400 < _ts < 3250368000:
            try:
                _t = datetime.datetime.fromtimestamp(
                    _ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                lines.append(f"| 编译时间戳 | {_t} |")
            except (OSError, ValueError):
                pass
    lines.append(f"| SHA-256 | `{sha}` |")
    lines.append(f"| 导入函数数 | {len(imports)} |")
    if pe_info:
        lines.append(f"| 数字签名 | {'已签名' if pe_info['signed'] else '无签名'} |")
        lines.append(f"| 节区数 | {len(pe_info['sections'])} |")
        if pe_info["high_entropy"]:
            he = ", ".join(f"{n}(熵{e})" for n, e in pe_info["high_entropy"])
            lines.append(f"| ⚠️ 高熵节区（可能压缩/加密/加壳） | {he} |")
        if pe_info.get("packer"):
            lines.append(f"| ⚠️ 节区名识别加壳器 | {', '.join(pe_info['packer'])} |")
        if pe_info.get("ep_outside"):
            lines.append("| ⚠️ 入口点异常 | 入口点不落任何节区，可能加壳/重定向 |")
        if pe_info.get("rwx_sections"):
            lines.append(f"| ⚠️ RWX 节区（可写可执行，可疑） | {', '.join(pe_info['rwx_sections'])} |")
        if pe_info["sections"]:
            lines.append("")
            lines.append("**节区明细（熵≥7.0 或 RWX 标⚠️）：**\n")
            lines.append("| 节区 | 熵 | 权限(X/R/W) | 原始大小 |")
            lines.append("|---|---|---|---|")
            for s in pe_info["sections"]:
                c = s.get("chars", 0)
                perm = _perm_str(c)
                warn = " ⚠️" if ((c & 0x20000000 and c & 0x80000000) or s["entropy"] >= 7.0) else ""
                lines.append(f"| {s['name']}{warn} | {s['entropy']} | {perm} | {s['rawsize']:,} |")
            lines.append("")
    if runtime:
        kind = []
        if runtime["dotnet"]:
            kind.append(".NET 托管")
        if runtime["go"]:
            kind.append("Go")
        if runtime["runtime"]:
            kind.append(runtime["runtime"])
        if runtime["packer"] and runtime["packer"] not in (pe_info.get("packer") or []):
            kind.append(f"打包器:{runtime['packer']}")
        lines.append(f"| 类型/运行时 | {', '.join(kind) if kind else '原生 C/C++ (未检出托管/运行时)'} |")
    lines.append("")

    lines.append("## 二、风险评分\n")
    lines.append(f"**总分：{total} / 100　等级：{level}**\n")
    if pe_info and pe_info["signed"] and total > 0:
        lines.append("> 样本已签名，系统/厂商库普遍导出高危 API，已对原始分做 0.35 减免，仅作参考。\n")
    if findings:
        lines.append("### 高危能力命中（计入评分）\n")
        lines.append("| 命中 API | 类别 | 分值 | 说明 |")
        lines.append("|---|---|---|---|")
        for f in findings:
            lines.append(f"| `{f['api']}` | {f['category']} | +{f['points']} | {f['explain']} |")
        lines.append("")
    else:
        lines.append("未命中计入评分的高危特征 API。\n")
    if common:
        lines.append("### 运行库常见项（仅提示，不计分）\n")
        for c in common:
            lines.append(f"- `{c['api']}` — {c['explain']}")
        lines.append("")

    lines.append("## 三、功能模块清单（先选模块，再深入）\n")
    lines.append("| # | 模块 | 置信度 | 精确API | 字符串 | 说明 |")
    lines.append("|---|---|---|---|---|---|")
    for i, m in enumerate(modules, 1):
        mark = " ⚠️" if m["key"] in HIGH_PRIORITY_KEYS else ""
        lines.append(
            f"| {i} | **{m['cn']}**{mark} | {m['confidence']} | {m['n_api']} | {m['n_str']} | {m['desc']} |")
    lines.append("")

    for m in modules:
        flag = "　⚠️优先深挖" if m["key"] in HIGH_PRIORITY_KEYS else ""
        lines.append(f"### {m['cn']}（{m['confidence']}置信）{flag}\n")
        if m["api_hits"]:
            lines.append("**命中导入 API：**")
            for a in m["api_hits"][:8]:
                lines.append(f"- `{a}`")
            if len(m["api_hits"]) > 8:
                lines.append(f"- …另有 {len(m['api_hits']) - 8} 条")
            probe = m["api_hits"][0].split("!")[-1]
            lines.append(f"\n> 深挖：在 Ghidra 中定位 `{probe}`，用 xrefs 找调用处、decompile 看伪代码；"
                         f"或用 REA CLI：`trace \"{path}\" \"{probe}\" --provider ghidra`")
            lines.append("")
        if m["dll_hits"]:
            lines.append(f"**相关库已导入（弱佐证）：** {', '.join(m['dll_hits'][:5])}\n")
        if m.get("net_ev"):
            ne = m["net_ev"]
            if ne["urls"]:
                lines.append("**外联 URL：**")
                for u in ne["urls"][:10]:
                    lines.append(f"- `{u}`")
                lines.append("")
            if ne["ips"]:
                lines.append("**公网 IP（建议核查归属/信誉）：** "
                             + ", ".join(f"`{i}`" for i in ne["ips"][:10]) + "\n")
            if ne["domains"]:
                lines.append("**域名（建议核查注册与信誉）：** "
                             + ", ".join(f"`{d}`" for d in ne["domains"][:10]) + "\n")
            if ne.get("private_ips"):
                lines.append("**本机/内网地址（非外联，仅供参考）：** "
                             + ", ".join(f"`{i}`" for i in ne["private_ips"][:10]) + "\n")
        if m["str_hits"]:
            lines.append("**命中字符串（节选）：**")
            for s in m["str_hits"][:8]:
                s_show = s if len(s) <= 80 else s[:77] + "..."
                lines.append(f"- `{s_show}`")
            lines.append("")

    lines.append("## 四、结论与下一步\n")

    # 自动总体判断（第一层参考，非最终结论）
    verdict = []
    if total >= 70:
        verdict.append("静态粗筛命中多项高危能力，建议优先按高危模块深挖并在沙箱中验证。")
    elif total >= 40:
        verdict.append("存在可疑能力，建议复核命中项是否被真正调用。")
    elif total >= 20:
        verdict.append("有少量需关注项，结合程序用途判断即可。")
    else:
        verdict.append("未命中显著高危能力，静态层面风险低。")
    if pe_info and pe_info["high_entropy"]:
        verdict.append("检测到高熵节区，疑似压缩/加密/加壳，建议先脱壳/解包再分析。")
    if pe_info and pe_info.get("rwx_sections"):
        verdict.append("存在可写可执行(RWX)节区，符合代码注入/自修改特征，建议重点核查。")
    netm = next((m for m in modules if m.get("net_ev")), None)
    if netm and (netm["net_ev"]["urls"] or netm["net_ev"]["ips"]):
        verdict.append("含硬编码外联地址，建议核对是否为已知合法服务器。")
    if runtime and runtime.get("packer"):
        verdict.append(f"疑似 {runtime['packer']} 加壳。")
    hit_hi = [m["cn"] for m in modules
              if m["key"] in HIGH_PRIORITY_KEYS and (m["n_api"] + m["n_str"]) > 0]
    # 组合联动判断：单特征易误报，多类高危并发更接近真实恶意链
    _keys = {m["key"] for m in modules if (m["n_api"] + m["n_str"]) > 0}
    # “外联”联动必须有真实硬编码地址（URL/公网IP/域名），仅有联网 API 能力不算
    _egress = bool(net_ev and (net_ev.get("urls") or net_ev.get("ips") or net_ev.get("domains")))
    if "injection" in _keys and "network" in _keys and _egress:
        verdict.append("⚠️ 注入能力叠加外联证据：符合“回连后注入/投放”特征链，建议重点核查。")
    if "injection" in _keys and "persistence" in _keys:
        verdict.append("⚠️ 注入叠加自启动：符合驻留木马特征，建议核查持久化落点。")
    if "creds" in _keys and "network" in _keys and _egress:
        verdict.append("⚠️ 凭据窃取叠加外联：符合窃取后外传特征，建议核对外联目的地。")
    if hit_hi:
        verdict.append("重点模块：" + "、".join(hit_hi) + "，建议优先对这些模块做调用链深挖。")
    if pe_info and pe_info.get("ep_outside"):
        verdict.append("入口点不落任何节区，疑似加壳/重定向，建议先脱壳再分析。")
    lines.append("### 总体判断（自动生成，仅供第一层参考）\n")
    for v in verdict:
        lines.append(f"- {v}")
    lines.append("")

    lines.append("- 本报告基于**导入表 + 字符串**静态粗筛，属于第一层判断，**不等于运行时行为**；"
                 "命中高危 API 只代表“具备该能力”，是否真正使用需结合反编译确认。")
    if runtime and runtime.get("hints"):
        lines.append("### 类型识别提示（换用对应工具链）\n")
        for h in runtime["hints"]:
            lines.append(f"- {h}")
        lines.append("")
    lines.append("- 建议：从上表选择你关心的模块，再用 Ghidra `trace` / `decompile` / `xrefs` "
                 "对该模块对应 API 做调用链深挖。")
    lines.append("- 静态推断条目请在最终结论中标注“静态推断”，勿直接判定为恶意。\n")
    return "\n".join(lines)


def _baseline_status(prev, sha, score):
    """基线对比状态：新增 / 已替换 / 风险上升(≥10) / 已见。prev 为旧库条目或 None。"""
    if prev is None:
        return "新增"
    if prev.get("sha") != sha:
        return "已替换"
    if score >= 0 and prev.get("score", 0) >= 0 and score - prev["score"] >= 10:
        return "风险上升"
    return "已见"


def _batch_tag(score, rc):
    """批量单文件判定标签：高危/可疑/非PE/失败/安全；超时或读取失败绝不算安全。"""
    if rc == 2:
        return "高危"
    if rc == 1:
        return "可疑"
    if rc == 3:
        return "非PE"
    if score < 0 or rc < 0:
        return "失败"
    return "安全"


def _batch_scan(batch_dir, min_confidence, report=None, baseline=None):
    """递归扫描目录下 exe/dll，子进程复用单文件逻辑，按风险分降序排名汇总。"""
    if not os.path.isdir(batch_dir):
        print(f"[错误] 批量目录不存在：{batch_dir}", file=sys.stderr)
        return 1

    old_db = {}
    if baseline and os.path.isfile(baseline):
        try:
            with open(baseline, "r", encoding="utf-8-sig") as f:
                old_db = json.load(f)
        except (OSError, json.JSONDecodeError):
            old_db = {}
    targets = []
    for root, _dirs, files in os.walk(batch_dir):
        for fn in files:
            if os.path.splitext(fn)[1].lower() in (".exe", ".dll"):
                p = os.path.join(root, fn)
                try:
                    if os.path.getsize(p) <= 300 * 1024 * 1024:
                        targets.append(p)
                except OSError:
                    pass
    if not targets:
        print("目录下未找到 exe/dll 文件。")
        return 0

    rows = []
    new_db = {}
    me = os.path.abspath(__file__)
    for p in targets:
        rel = os.path.relpath(p, batch_dir)
        try:
            with open(p, "rb") as f:
                sha = hashlib.sha256(f.read()).hexdigest()
        except OSError:
            sha = ""
        try:
            proc = subprocess.run(
                [sys.executable, me, p, "--quiet",
                 "--min-confidence", min_confidence],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=60)
            m = re.search(r"风险评分：(\d+)/100", proc.stdout)
            score = int(m.group(1)) if m else -1
            rc = proc.returncode
        except (subprocess.TimeoutExpired, OSError, UnicodeDecodeError):
            score, rc = -1, -1

        # 基线对比：新增 / 已替换 / 风险上升(≥10) / 已见；非PE单列，读取/超时失败不污染基线库
        if score >= 0:
            status = _baseline_status(old_db.get(rel), sha, score)
            new_db[rel] = {"sha": sha, "score": score,
                           "ts": datetime.datetime.now().isoformat(timespec="seconds")}
        elif rc == 3:
            status = "非PE"
        else:
            status = "失败"
        rows.append((score, rc, rel, status))

    rows.sort(key=lambda r: r[0], reverse=True)
    print(f"批量分诊：共 {len(rows)} 个文件（按风险分降序）\n")
    print(f"{'评分':>4}  {'退出码':>4}  {'判定':<4}  {'基线':<6} 文件")
    hi = sus = 0
    md_rows = []
    for score, rc, rel, status in rows:
        tag = _batch_tag(score, rc)
        if tag == "高危":
            hi += 1
        elif tag == "可疑":
            sus += 1
        sc = str(score) if score >= 0 else "ERR"
        print(f"{sc:>4}  {rc:>4}  {tag:<4}  {status:<6} {rel}")
        md_rows.append((sc, rc, tag, status, rel))
    print(f"\n汇总：高危 {hi}，可疑 {sus}，其余安全/低危/非PE。")

    if baseline:
        try:
            with open(baseline, "w", encoding="utf-8") as f:
                json.dump(new_db, f, ensure_ascii=False, indent=2)
            print(f"基线指纹库已更新：{baseline}")
        except OSError as e:
            print(f"[警告] 基线库写入失败：{e}", file=sys.stderr)

    if report:
        try:
            md = ["# 批量分诊排名\n",
                  f"- 目录：`{batch_dir}`",
                  f"- 文件数：{len(md_rows)}　高危 {hi}　可疑 {sus}\n",
                  "| 评分 | 退出码 | 判定 | 基线 | 文件 |", "|---|---|---|---|---|"]
            for sc, rc, tag, status, rel in md_rows:
                md.append(f"| {sc} | {rc} | {tag} | {status} | `{rel}` |")
            with open(report, "w", encoding="utf-8-sig") as f:
                f.write("\n".join(md) + "\n")
            print(f"汇总排名已写入：{report}")
        except OSError as e:
            print(f"[警告] 汇总报告写入失败：{e}", file=sys.stderr)

    return 2 if hi else (1 if sus else 0)


# ----------------------------------------------------------------------------
# 主流程
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="EXE 模块化拆分粗筛器（零依赖，Ghidra 前第一层静态分析）",
        epilog="示例：\n"
               "  pe_module_scan app.exe --report r.md --json r.json\n"
               "  pe_module_scan app.exe --quiet            # 流水线，靠退出码判定\n"
               "  pe_module_scan app.exe --min-confidence high\n"
               "  pe_module_scan --batch D:\\downloads --report rank.md      # 批量分诊排名\n"
               "  pe_module_scan --batch D:\\downloads --baseline db.json     # 复扫对比新增/替换/上升\n"
               "退出码：0 安全/低危  1 可疑  2 高危  3 非PE")
    ap.add_argument("exe", nargs="?", help="待分析的 exe/dll 路径")
    ap.add_argument("--batch", help="批量分诊目录：递归扫描其中 exe/dll，按风险分排名汇总")
    ap.add_argument("--baseline", help="基线指纹库 JSON 路径：复扫时对比，标注新增/替换/风险上升/已见")
    ap.add_argument("--report", help="输出中文 Markdown 报告路径")
    ap.add_argument("--json", dest="json_out", help="输出结构化 JSON 结果路径")
    ap.add_argument("--min-confidence", choices=["high", "medium", "low"],
                    default="low", help="只显示达到该置信度的模块（high=≥2精确API/medium=1/low=全显，默认 low）")
    ap.add_argument("--quiet", action="store_true",
                    help="精简输出，只打印风险结论与退出码（供流水线/CI）")
    ap.add_argument("--version", action="version", version="pe_module_scan 1.0")
    args = ap.parse_args()

    if args.batch:
        sys.exit(_batch_scan(args.batch, args.min_confidence, args.report, args.baseline))

    if not args.exe:
        ap.error("请提供待分析文件路径，或用 --batch 指定批量分诊目录")
    path = args.exe
    if not os.path.isfile(path):
        print(f"[错误] 文件不存在：{path}", file=sys.stderr)
        sys.exit(1)

    # 大小上限 300MB：避免把超大文件整体读入内存；常规 PE 远小于此
    if os.path.getsize(path) > 300 * 1024 * 1024:
        print("[错误] 文件超过 300MB，超出本粗筛器适用范围，请先裁剪或用专用工具。",
              file=sys.stderr)
        sys.exit(1)

    try:
        with open(path, "rb") as f:
            data = f.read()
    except (PermissionError, OSError) as e:
        print(f"[错误] 无法读取文件：{e}", file=sys.stderr)
        sys.exit(1)

    imports, is64, _sec = parse_pe_imports(data)
    if imports is None:
        fmt, cmd = detect_artifact_format(data)
        if fmt:
            print(f"[非PE] 识别为 {fmt}；本粗筛器仅支持 Windows PE。", file=sys.stderr)
            print(f"       请改用原版 rea-agents：npx -y rea-agents@6.7.0 {cmd} \"{path}\"",
                  file=sys.stderr)
        else:
            print("[错误] 不是有效 PE 文件（MZ/PE 头校验失败），本脚本仅支持 Windows PE。",
                  file=sys.stderr)
        sys.exit(3)

    pe_info = compute_pe_info(data)
    strings = extract_strings(data)
    net_ev = extract_network_evidence(strings)
    runtime = detect_runtime(data, strings)
    modules = classify(imports, strings)
    # 有 URL/IP/域名证据时，确保网络模块出现并挂载证据
    net_mod = next((m for m in modules if m["key"] == "network"), None)
    if net_ev["urls"] or net_ev["ips"] or net_ev["domains"]:
        if net_mod is None:
            net_mod = {"key": "network", "cn": "网络通信", "desc": "联网/外联证据",
                       "confidence": "中", "api_hits": [], "str_hits": [],
                       "dll_hits": [], "common_hits": [], "n_api": 0, "n_str": 0}
            modules.append(net_mod)
        net_mod["net_ev"] = net_ev

    # --min-confidence 过滤：high=n_api>=2, medium=n_api>=1, low=全显；
    # 纯字符串高危模块（勒索/反沙盒等，n_api=0 但命中字符串）始终保留
    _min = {"high": 2, "medium": 1, "low": 0}[args.min_confidence]
    modules = [m for m in modules if _keep_module(m, _min)]
    # 高危模块置顶，其余按精确 API 数降序
    modules.sort(key=lambda m: (0 if m["key"] in HIGH_PRIORITY_KEYS else 1,
                                -m["n_api"], -m["n_str"]))

    _dir = os.path.normcase(os.path.dirname(os.path.abspath(path)))
    _sysdirs = (os.path.normcase(r"c:\windows\system32"),
                os.path.normcase(r"c:\windows\syswow64"))
    trusted = bool(pe_info and pe_info["signed"]) or \
        any(_dir == d or _dir.startswith(d + os.sep) for d in _sysdirs)
    total, level, findings, common = score(imports, trusted=trusted)

    _kind = "DLL" if (pe_info and pe_info.get("is_dll")) else "EXE"
    _sub = {2: "GUI图形界面", 3: "控制台"}.get(pe_info.get("subsystem") if pe_info else None, "")
    _sub_txt = f"　界面：{_sub}" if _sub else ""
    print(f"样本：{os.path.basename(path)}　类型：{_kind}{_sub_txt}　架构：{'x64' if is64 else 'x86'}　"
          f"导入函数 {len(imports)}　字符串 {len(strings)}")
    print(f"风险评分：{total}/100　{level}")
    if not args.quiet:
        print()
        print("功能模块清单：")
        for i, m in enumerate(modules, 1):
            flag = " ⚠️优先" if m["key"] in HIGH_PRIORITY_KEYS else ""
            print(f"  {i:>2}. [{m['confidence']}置信] {m['cn']}{flag} "
                  f"(API {m['n_api']}, 字符串 {m['n_str']}) — {m['desc']}")
        if findings:
            print("\n高危命中（计分）：")
            for f in findings:
                print(f"  +{f['points']} [{f['category']}] {f['api']} — {f['explain']}")
        if common:
            print("\n运行库常见项（不计分）：")
            for c in common:
                print(f"  · {c['api']} — {c['explain']}")
        if net_ev["urls"] or net_ev["ips"] or net_ev["domains"]:
            print("\n外联证据（公网，建议核查归属/信誉）：")
            for u in net_ev["urls"][:10]:
                print(f"  URL  {u}")
            for i in net_ev["ips"][:10]:
                print(f"  IP   {i}")
            for d in net_ev["domains"][:10]:
                print(f"  域名 {d}")
        if net_ev.get("private_ips"):
            print("\n本机/内网地址（非外联，仅供参考，不计可疑）：")
            for i in net_ev["private_ips"][:10]:
                print(f"  内网 {i}")
        if runtime:
            kind = []
            if runtime["dotnet"]:
                kind.append(".NET")
            if runtime["go"]:
                kind.append("Go")
            if runtime["runtime"]:
                kind.append(runtime["runtime"])
            if runtime["packer"] and runtime["packer"] not in (pe_info.get("packer") or []):
                kind.append(runtime["packer"])
            if kind:
                print(f"类型/运行时：{', '.join(kind)}")
        if pe_info:
            _ts = pe_info.get("timestamp") or 0
            if 86400 < _ts < 3250368000:  # 1972 ~ 2075 合理范围
                try:
                    _t = datetime.datetime.fromtimestamp(
                        _ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                    print(f"编译时间戳：{_t}")
                except (OSError, ValueError):
                    pass
            if pe_info["signed"]:
                print("\n数字签名：已签名")
            if pe_info["high_entropy"]:
                print("⚠️ 高熵节区（可能压缩/加密/加壳）："
                      + ", ".join(f"{n}(熵{e})" for n, e in pe_info["high_entropy"]))
            if pe_info.get("packer"):
                print(f"⚠️ 节区名识别加壳器：{', '.join(pe_info['packer'])}")
            if pe_info.get("ep_outside"):
                print("⚠️ 入口点不落任何节区，可能加壳/重定向")
            if pe_info.get("rwx_sections"):
                print(f"⚠️ RWX 节区（可写可执行，可疑）：{', '.join(pe_info['rwx_sections'])}")

    if args.report:
        report = build_report(path, data, imports, is64, modules, total, level, findings, common, pe_info, runtime, net_ev)
        try:
            with open(args.report, "w", encoding="utf-8-sig") as f:
                f.write(report)
            print(f"\n报告已写入：{args.report}")
        except OSError as e:
            print(f"[警告] 报告写入失败：{e}", file=sys.stderr)

    if args.json_out:
        payload = {
            "file": os.path.basename(path),
            "size": len(data),
            "is64": is64,
            "sha256": hashlib.sha256(data).hexdigest(),
            "import_count": len(imports),
            "risk": {"score": total, "level": level, "findings": findings,
                     "common": common,
                     "exit_code": 2 if level == "高危" else (1 if level.startswith("可疑") else 0)},
            "pe": pe_info,
            "runtime": runtime,
            "network_evidence": net_ev,
            "modules": modules,
        }
        try:
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            print(f"JSON 已写入：{args.json_out}")
        except OSError as e:
            print(f"[警告] JSON 写入失败：{e}", file=sys.stderr)

    # 退出码供流水线/CI 判定：0 安全/低危，1 可疑需复核，2 高危
    if level == "高危":
        sys.exit(2)
    elif level.startswith("可疑"):
        sys.exit(1)


if __name__ == "__main__":
    main()
