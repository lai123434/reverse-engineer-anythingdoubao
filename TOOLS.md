# 配套分析工具链（本机已安装）

REA 粗筛器（`tools/pe_module_scan.py`）是 Ghidra 前的第一层静态分诊。下面是本机已装好的
配套工具，按「粗筛 → 查壳/脱壳 → 深挖」顺序衔接。路径为本机实际位置，换机器需重新安装。

## 流程串联

```
pe_module_scan.py（第一层粗筛打分/模块清单）
        │  识别出加壳/可疑
        ▼
DIE（查壳/识别编译器打包器）→ UPX（仅 UPX 壳脱壳）
        │
        ▼
FLOSS（提取混淆/栈字符串，补明文字符串）
        │
        ▼
x64dbg（动态单步跟踪） / Ghidra（静态反编译深挖）
```

> DIE 与 FLOSS 已通过开关串进粗筛器，一条命令跑完；缺工具自动跳过，不影响主流程：
> `python tools\pe_module_scan.py app.exe --die --floss --report report.md`
> UPX 不自动脱壳（避免改写样本），检测到 UPX 壳时报告里直接给出 `upx -d` 手动命令。


## 工具清单

| 工具 | 版本 | 位置 / 启动 | 用途 |
|------|------|------------|------|
| DIE (Detect It Easy) | 3.21 | GUI `C:\Tools\die\die\die.exe`；控制台 `diec.exe` | 查壳、识别编译器/链接器/打包器，比粗筛器只看节区名准 |
| UPX | 5.2.1 | `C:\Tools\upx\upx-5.2.1-win64\upx.exe` | 仅对 UPX 壳脱壳：`upx -d packed.exe` |
| FLOSS | 3.1.1 | 命令 `floss`（winget 安装，新终端生效） | 提取栈字符串/解码字符串，补粗筛器只提明文字符串的短板 |
| x64dbg | 2026.05.27 | `C:\Tools\x64dbg\release\x96dbg.exe`（启动器，选 x86/x64） | 动态调试，让程序跑起来单步跟踪真实行为 |
| Ghidra | 12.1.4 | `C:\Tools\ghidra_12.1.4_PUBLIC`（已装，需 Java 21，已具备） | 静态反编译深挖 |

## 常用命令

```bash
# DIE 控制台识别样本（壳/编译器/链接器）
"C:\Tools\die\die\diec.exe" suspect.exe

# UPX 脱壳（只对 UPX 有效，其他壳不要用）
"C:\Tools\upx\upx-5.2.1-win64\upx.exe" -d packed.exe

# FLOSS：只提静态明文字符串 / 全量含栈与解码字符串
floss --only static -n 6 suspect.exe
floss suspect.exe

# 粗筛器第一层打分（本仓库）
python tools\pe_module_scan.py suspect.exe --report report.md
```

## 边界提醒

- UPX 只能脱 UPX 壳；VMProtect/Themida/ASPack 等需专用脱壳或手动，不要硬脱。
- FLOSS 的栈/解码字符串依赖仿真，大文件较慢，可先用 `--only static`。
- 动态调试（x64dbg）和真实恶意样本务必在隔离虚拟机内进行，不在主机直接跑。
