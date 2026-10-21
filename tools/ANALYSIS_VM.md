# 隔离分析虚拟机操作手册（VirtualBox / dc / Win10 x64）

> 用途：在隔离 VM 内运行真实样本，配合 `pe_module_scan.py` 静态粗筛 + 动态观察。
> 铁律：**样本只进 VM，绝不落盘主机；每次分析后还原快照。**

## 一、已完成的加固（2026-10-21）

- 已移除共享文件夹 `share`（原直通主机 `C:\VBoxShare`）——回写通道已切断。
- 已建干净基线快照：`clean-base`（UUID e8052623-0ee0-4e55-86ba-91f7e8d0c6fd）。
- 剪贴板 `disabled`、拖拽 `disabled`、文件传输 `off`、VRDE 关闭。
- 网卡：NAT（默认不被主机入站；分析时按下方命令手动断网）。

VBoxManage 路径：`C:\Program Files\Oracle\VirtualBox\VBoxManage.exe`

## 二、每次分析流程

```powershell
$vbm = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

# 1. 启动
& $vbm startvm "dc" --type gui

# 2. 进系统后、投放前断网卡（防样本外联扩散）
& $vbm controlvm "dc" setlinkstate1 off

# 3. 在 VM 内投放样本、运行、观察（可用 pe_module_scan.py 先静态粗筛）

# 4. 分析完关机并还原干净基线（彻底清除痕迹）
& $vbm controlvm "dc" poweroff
& $vbm snapshot "dc" restore "clean-base"
```

需要重新联网下载样本时，先恢复链路：
```powershell
& $vbm controlvm "dc" setlinkstate1 on
```

## 三、样本来源（在 VM 内下载，勿落主机）

- **EICAR 测试串**（无害，仅验证杀软/链路）：`https://eicar.org` 下载 eicar.com。
- **MalwareBazaar**（abuse.ch，匿名免费）：`https://bazaar.abuse.ch`，按哈希/标签下载，下载动作在 VM 内完成。
- 不从不明论坛/网盘下载，避免捆绑与法律风险。

## 四、纪律

- 主机不保存任何真实样本；下载只在 VM 内进行。
- 每轮分析后必须 `restore clean-base`，不要在脏快照上叠加。
- 静态粗筛结论（本脚本）是第一层，动态行为以 VM 内观察为准，二者交叉印证。
