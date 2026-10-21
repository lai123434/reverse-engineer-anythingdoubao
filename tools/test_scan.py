# -*- coding: utf-8 -*-
"""
回归测试：锁定基线行为，每轮迭代后运行 `python tools/test_scan.py` 守护。

覆盖：
  1. 高危伪造样本必须得满分并识别注入/键盘记录/提权/网络模块。
  2. notepad.exe（若存在）必须 0 分，且只出现合理模块，不得出现高危模块。
  3. 纯函数：归一化、PE 解析对非 PE 返回 None。
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location("mod", os.path.join(HERE, "pe_module_scan.py"))
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)

PASS, FAIL = 0, 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}")


# --- 1. 高危伪造样本 ---
print("[1] 高危伪造样本")
fake = [
    ("kernel32.dll", "CreateRemoteThread"),
    ("kernel32.dll", "VirtualAllocEx"),
    ("kernel32.dll", "WriteProcessMemory"),
    ("advapi32.dll", "AdjustTokenPrivileges"),
    ("advapi32.dll", "LookupPrivilegeValueW"),
    ("user32.dll", "SetWindowsHookExW"),
    ("user32.dll", "GetAsyncKeyState"),
    ("winmm.dll", "waveInOpen"),
    ("ws2_32.dll", "socket"),
    ("ws2_32.dll", "connect"),
    ("advapi32.dll", "CredEnumerateA"),
    ("advapi32.dll", "ClearEventLogW"),
    ("advapi32.dll", "DeleteService"),
    ("mapi32.dll", "MapiSendMail"),
    ("wininet.dll", "FtpPutFileW"),
    ("kernel32.dll", "CheckRemoteDebuggerPresent"),
    ("ntdll.dll", "NtWriteVirtualMemory"),
    ("ntdll.dll", "NtUnmapViewOfSection"),
    ("ntdll.dll", "NtLoadDriver"),
    ("advapi32.dll", "ImpersonateLoggedOnUser"),
    ("wevtapi.dll", "EvtClearLog"),
]
total, level, findings, _common = mod.score(fake)
_fcats = {f["category"] for f in findings}
mods = {m["key"]: m for m in mod.classify(
    fake, ["currentversion\\run", "https://c2.example.com/a",
           "running in vmware", "winlogon", "your files are encrypted"])}
check("识别自启动持久化模块", "persistence" in mods)
check("识别勒索特征模块", "ransom" in mods)
check("识别反调试模块", "anti_debug" in mods and mods["anti_debug"]["n_api"] >= 1)
check("高危总分=100", total == 100)
check("等级=高危", level == "高危")
check("识别进程注入模块", "injection" in mods and mods["injection"]["n_api"] >= 2)
check("识别键盘记录模块", "keylog" in mods and mods["keylog"]["n_api"] >= 2)
check("识别提权模块", "privilege" in mods and mods["privilege"]["n_api"] >= 2)
check("识别网络模块(ws2_32限定)", "network" in mods and mods["network"]["n_api"] >= 2)
check("识别凭据窃取/反取证模块", "creds" in mods and mods["creds"]["n_api"] >= 2)
check("识别反虚拟机模块(字符串)", "anti_vm" in mods)
check("数据外泄被计分(MAPI/FTP)", "数据外泄" in _fcats)
check("删除服务归服务模块", "service" in mods and mods["service"]["n_api"] >= 1)
check("高危发现条数>=10", len(findings) >= 10)

# --- 2. notepad 基线 ---
np = r"C:\Windows\System32\notepad.exe"
if os.path.isfile(np):
    print("[2] notepad.exe 基线")
    data = open(np, "rb").read()
    imports, is64, _ = mod.parse_pe_imports(data)
    check("notepad 解析为 PE", imports is not None)
    strings = mod.extract_strings(data)
    total, level, findings, _c = mod.score(imports)
    mods = {m["key"]: m for m in mod.classify(imports, strings)}
    check("notepad 风险分=0", total == 0)
    check("notepad 无高危计分发现", len(findings) == 0)
    check("notepad 含 GUI 模块", "gui" in mods)
    check("notepad 含文件读写模块", "fileio" in mods)
    check("notepad 不得出现注入模块", "injection" not in mods)
    check("notepad 不得出现键盘记录模块", "keylog" not in mods)
    check("notepad 不得出现提权模块", "privilege" not in mods)
    _pi = mod.compute_pe_info(data)
    check("notepad 入口点落在节区(非加壳)", _pi is not None and not _pi["ep_outside"])
    check("notepad 无 RWX 可写可执行节区", _pi is not None and _pi["rwx_sections"] == [])
    check("notepad 识别为EXE非DLL", _pi is not None and _pi["is_dll"] is False)
    check("notepad 含编译时间戳字段", _pi is not None and isinstance(_pi["timestamp"], int))
    check("notepad 为GUI子系统(2)", _pi is not None and _pi["subsystem"] == 2)
else:
    print("[2] notepad.exe 不存在，跳过")

# --- 2b. calc.exe 宽松基线（合法程序不得判高危/命中注入键盘提权模块） ---
calc = r"C:\Windows\System32\calc.exe"
if os.path.isfile(calc):
    print("[2b] calc.exe 宽松基线")
    cdata = open(calc, "rb").read()
    cimports, _c64, _ = mod.parse_pe_imports(cdata)
    cstr = mod.extract_strings(cdata)
    ctotal, clevel, cfind, _c = mod.score(cimports)
    cmods = {m["key"]: m for m in mod.classify(cimports, cstr)}
    check("calc 总分 <20（低关注）", ctotal < 20)
    check("calc 等级非高危", clevel != "高危")
    check("calc 不得出现注入模块", "injection" not in cmods)
    check("calc 不得出现键盘记录模块", "keylog" not in cmods)
    check("calc 不得出现提权模块", "privilege" not in cmods)
else:
    print("[2b] calc.exe 不存在，跳过")

# --- 2c. 系统目录样本宽松基线（trusted 减免后不得判高危） ---
print("[2c] 系统目录样本宽松基线")
sys_samples = [r"C:\Windows\System32\explorer.exe",
               r"C:\Windows\SysWOW64\explorer.exe",
               r"C:\Windows\System32\taskmgr.exe",
               r"C:\Windows\SysWOW64\regedit.exe",
               r"C:\Windows\SysWOW64\notepad.exe"]
for sp in sys_samples:
    if not os.path.isfile(sp):
        print(f"  跳过 {os.path.basename(sp)}（不存在）")
        continue
    sd = open(sp, "rb").read()
    si, _s64, _ = mod.parse_pe_imports(sd)
    st, slvl, _sf, _sc = mod.score(si, trusted=True)
    check(f"{os.path.basename(sp)} 减免后 <20", st < 20)
    check(f"{os.path.basename(sp)} 非高危", slvl != "高危")

# --- 3. 纯函数 ---
print("[3] 纯函数")
check("归一化去W后缀", mod._norm_api("CreateWindowExW") == "createwindowex")
check("归一化小写", mod._norm_api("MessageBoxA") == "messagebox")
check("归一化保留Ex后缀", mod._norm_api("CreateRemoteThreadEx") == "createremotethreadex")
check("非PE返回None", mod.parse_pe_imports(b"not a pe")[0] is None)
check("纯字符串高危模块high过滤保留",
      mod._keep_module({"key": "ransom", "n_api": 0, "n_str": 2}, 2))
check("普通纯字符串模块high过滤滤掉",
      not mod._keep_module({"key": "fileio", "n_api": 0, "n_str": 1}, 2))
check("单API在high过滤滤掉",
      not mod._keep_module({"key": "fileio", "n_api": 1, "n_str": 0}, 2))
check("单API在medium过滤保留",
      mod._keep_module({"key": "fileio", "n_api": 1, "n_str": 0}, 1))
_tf, _, _, _ = mod.score([("kernel32.dll", "CreateRemoteThread")], trusted=False)
_tt, _, _, _ = mod.score([("kernel32.dll", "CreateRemoteThread")], trusted=True)
check("trusted减免后分数下降", _tt < _tf and _tt == round(_tf * 0.35))
_cap, _, _, _ = mod.score(
    [("k.dll", "CreateRemoteThread"), ("k.dll", "NtCreateThreadEx"),
     ("k.dll", "RtlCreateUserThread"), ("k.dll", "SetWindowsHookEx"),
     ("k.dll", "WriteProcessMemory"), ("k.dll", "CryptEncrypt"),
     ("k.dll", "CredEnumerate")], trusted=False)
check("总分封顶100", _cap == 100)
check("高API模块high过滤保留",
      mod._keep_module({"key": "injection", "n_api": 3, "n_str": 0}, 2))
_ev = mod.extract_network_evidence(["192.168.1.5", "10.0.0.2", "172.16.0.1",
                                   "169.254.1.1", "8.8.8.8", "127.0.0.1"])
check("内网/保留IP被剔除,公网保留", _ev["ips"] == ["8.8.8.8"])
_ev2 = mod.extract_network_evidence(["https://example.com/a", "https://c2.ru/x"])
check("占位域名example.com被剔除", "example.com" not in _ev2["domains"]
      and "c2.ru" in _ev2["domains"])
check("检出CEF运行时", mod.detect_runtime(b"MZ", ["libcef.dll"])["runtime"] == "CEF")
check("检出Electron运行时", mod.detect_runtime(b"MZ", ["electron.app"])["runtime"].startswith("Electron"))
check("短buffer运行时检测不崩", mod.detect_runtime(b"MZ", [])["runtime"] is None)
check("截断MZ头导入解析返回None", mod.parse_pe_imports(b"MZ\x90")[0] is None)
check("截断MZ头PE信息返回None", mod.compute_pe_info(b"MZ\x90") is None)
# 伪造 PE\0\0 头但 optional header 落在文件外：不得抛 struct/IndexError，返回 None
_fk = bytearray(0x60)
_fk[0:2] = b"MZ"
_fk[0x3C:0x40] = bytes([0x50, 0, 0, 0])
_fk[0x50:0x54] = b"PE\0\0"
_fkb = bytes(_fk)
check("PE头截断导入解析不崩返回None", mod.parse_pe_imports(_fkb)[0] is None)
check("PE头截断PE信息不崩返回None", mod.compute_pe_info(_fkb) is None)
# detect_runtime 对截断PE不抛异常
check("截断PE运行时检测不崩", isinstance(mod.detect_runtime(_fkb, [])["hints"], list))
_zero, _zlvl, _zf, _zc = mod.score([])
check("空导入打分为0且安全", _zero == 0 and "安全" in _zlvl)
_c2 = {x["key"]: x for x in mod.classify(
    [("kernel32.dll", "CreateRemoteThread"), ("kernel32.dll", "VirtualAllocEx")], [])}
check("2个API=高置信", _c2["injection"]["confidence"] == "高")
_c1 = {x["key"]: x for x in mod.classify([("kernel32.dll", "CreateRemoteThread")], [])}
check("1个API=中置信", _c1["injection"]["confidence"] == "中")
_cs = {x["key"]: x for x in mod.classify([], ["vmware"])}
check("纯字符串=低置信", _cs["anti_vm"]["confidence"].startswith("低"))
check("节区RX权限解码", mod._perm_str(0x60000020) == "XR-")
check("节区RWX权限解码", mod._perm_str(0xE0000000) == "XRW")
_s, _lv, _fd, _cm = mod.score([("ntdll.dll", "NtWriteVirtualMemory")])
check("原生写远程内存命中计分", any("NtWriteVirtualMemory" in f["api"] for f in _fd) and _s > 0)
_s2, _, _fd2, _ = mod.score([("advapi32.dll", "ImpersonateLoggedOnUser")])
check("令牌模拟命中计分", any("ImpersonateLoggedOnUser" in f["api"] for f in _fd2) and _s2 > 0)
_s3, _, _fd3, _ = mod.score([("wevtapi.dll", "EvtClearLog")])
check("现代日志清除命中计分", any("EvtClearLog" in f["api"] for f in _fd3) and _s3 > 0)
_s4, _, _fd4, _ = mod.score([("ntdll.dll", "NtUnmapViewOfSection")])
check("进程空洞命中计分", any("NtUnmapViewOfSection" in f["api"] for f in _fd4) and _s4 > 0)
_cr = {x["key"]: x for x in mod.classify([], ["logins.json", "cookies"])}
check("浏览器凭据路径归creds模块", "creds" in _cr and _cr["creds"]["n_str"] >= 2)
_s5, _, _fd5, _ = mod.score([("ntdll.dll", "NtLoadDriver")])
check("内核驱动加载命中计分", any("NtLoadDriver" in f["api"] for f in _fd5) and _s5 > 0)
_sx = mod.extract_strings(b"hello\x00hello world\x00")
check("字符串提取ASCII并去重", "hello world" in _sx and len(_sx) == len(set(_sx)))
_ev3 = mod.extract_network_evidence(["HTTPS://C2.RU/x"])
check("域名大写归一为小写", _ev3["domains"] == ["c2.ru"])
_ev4 = mod.extract_network_evidence(["http://a.io/p", "https://b.io/q"])
check("URL被提取保留", len(_ev4["urls"]) == 2)
_ev5 = mod.extract_network_evidence(["version 5.1.0.0", "8.8.8.8"])
check("版本号IP(.0结尾)被剔除", "5.1.0.0" not in _ev5["ips"] and "8.8.8.8" in _ev5["ips"])
_ev6 = mod.extract_network_evidence(["kernel32.dll", "c2.ru"])
check("扩展名伪域名被剔除", "kernel32.dll" not in _ev6["domains"] and "c2.ru" in _ev6["domains"])
_ev7 = mod.extract_network_evidence(["host.local", "c2.ru"])
check("非白名单TLD(.local)被剔除", "host.local" not in _ev7["domains"] and "c2.ru" in _ev7["domains"])
_ev8 = mod.extract_network_evidence(["172.16.0.1", "172.31.255.254", "8.8.8.8"])
check("172.16-31内网段被剔除", "172.16.0.1" not in _ev8["ips"]
      and "172.31.255.254" not in _ev8["ips"] and "8.8.8.8" in _ev8["ips"])
_ev9 = mod.extract_network_evidence(["127.0.0.1", "169.254.1.1", "8.8.8.8"])
check("回环/APIPA被剔除", "127.0.0.1" not in _ev9["ips"]
      and "169.254.1.1" not in _ev9["ips"] and "8.8.8.8" in _ev9["ips"])
check("回环/内网归入private_ips参考",
      "127.0.0.1" in _ev9["private_ips"] and "169.254.1.1" in _ev9["private_ips"]
      and "8.8.8.8" not in _ev9["private_ips"])
_rt = mod.detect_runtime(b"MZ", ["Go build ID: abcdef123456"])
check("检出Go运行时", _rt["go"] is not None and any("Go" in h for h in _rt["hints"]))
_rtu = mod.detect_runtime(b"MZ", ["UPX!"])
check("检出UPX加壳", _rtu["packer"] == "UPX")
check("识别ELF格式", mod.detect_artifact_format(b"\x7fELF\x02\x01")[0].startswith("ELF"))
check("识别Mach-O格式", "Mach-O" in mod.detect_artifact_format(b"\xfe\xed\xfa\xce")[0])
check("识别ZIP/APK格式", "ZIP" in mod.detect_artifact_format(b"PK\x03\x04")[0])
check("未知格式返回None", mod.detect_artifact_format(b"hello world") == (None, None))
check("批量目录不存在返回1", mod._batch_scan(r"C:\__no_such_dir_xyz__", "low") == 1)
check("基线-新增", mod._baseline_status(None, "abc", 5) == "新增")
check("基线-已替换(哈希变)", mod._baseline_status({"sha": "old", "score": 5}, "new", 5) == "已替换")
check("基线-风险上升(≥10)", mod._baseline_status({"sha": "s", "score": 10}, "s", 25) == "风险上升")
check("基线-已见(同哈希小波动)", mod._baseline_status({"sha": "s", "score": 10}, "s", 12) == "已见")
# MAPI 邮件外泄经 mapi32.dll 归入网络模块（scope 含 mapi32.dll）
_mapi = {x["key"]: x for x in mod.classify([("mapi32.dll", "MapiSendMail")], [])}
check("MapiSendMail归network模块", "network" in _mapi and _mapi["network"]["n_api"] >= 1)
# 批量标签：超时/读取失败必须标“失败”，绝不算安全
check("批量失败标失败而非安全", mod._batch_tag(-1, -1) == "失败")
check("批量0分安全", mod._batch_tag(0, 0) == "安全")
check("批量高危标签", mod._batch_tag(70, 2) == "高危")
check("批量可疑标签", mod._batch_tag(45, 1) == "可疑")
check("批量非PE标签", mod._batch_tag(-1, 3) == "非PE")
_pm = {x["key"]: x for x in mod.classify([], ["userinit", "encodedcommand"])}
check("驻留串归persistence模块", "persistence" in _pm and _pm["persistence"]["n_str"] >= 2)
_pm2 = {x["key"]: x for x in mod.classify([], ["sethc.exe", "image file execution options"])}
check("劫持串归persistence模块", "persistence" in _pm2 and _pm2["persistence"]["n_str"] >= 2)
_cr2 = {x["key"]: x for x in mod.classify([], ["history", "bookmarks"])}
check("浏览记录归creds模块", "creds" in _cr2 and _cr2["creds"]["n_str"] >= 2)
check("空缓冲区熵=0", mod._shannon(b"") == 0.0)
check("同字节熵=0", mod._shannon(b"\x41" * 64) == 0.0)
check("多样本熵>0", mod._shannon(bytes(range(256))) > 0)
_ij = {x["key"]: x for x in mod.classify([("ntdll.dll", "NtWriteVirtualMemory")], [])}
check("原生写内存归injection模块", "injection" in _ij and _ij["injection"]["n_api"] >= 1)
_pv = {x["key"]: x for x in mod.classify([("advapi32.dll", "ImpersonateLoggedOnUser")], [])}
check("令牌模拟归privilege模块", "privilege" in _pv and _pv["privilege"]["n_api"] >= 1)
# 外联联动必须有真实地址：仅有联网API能力不触发“注入+外联”链
_mk = lambda key, n: {"key": key, "cn": key, "desc": "", "confidence": "高",
                     "api_hits": [], "str_hits": [], "dll_hits": [],
                     "common_hits": [], "n_api": n, "n_str": 0}
_rep1 = mod.build_report("x.exe", b"MZ", [], False,
                         [_mk("injection", 2), _mk("network", 2)],
                         25, "低危", [], [], None, None,
                         net_ev={"urls": [], "ips": [], "domains": []})
check("无外联地址不触发注入+外联链", "回连后注入" not in _rep1)
_rep2 = mod.build_report("x.exe", b"MZ", [], False,
                         [_mk("injection", 2), _mk("network", 2)],
                         70, "高危", [], [], None, None,
                         net_ev={"urls": [], "ips": ["8.8.8.8"], "domains": []})
check("有外联地址触发注入+外联链", "回连后注入" in _rep2)

# 对账：所有计分API归一化后都应能归到某个报告模块
_all_mod_apis = {mod._norm_api(a) for mm in mod.MODULES for a in mm["apis"]}
_unmapped = [k for k in mod.HIGH_RISK if mod._norm_api(k) not in _all_mod_apis]
if _unmapped:
    print("  未归类计分API:", _unmapped)
check("计分API全部可归到模块", _unmapped == [])

print(f"\n结果：{PASS} 通过 / {FAIL} 失败")
sys.exit(1 if FAIL else 0)
