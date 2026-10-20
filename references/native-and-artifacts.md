# Native, Managed, and Packaged Artifacts — CLI 版

## Go 二进制元数据
```powershell
npx -y rea-agents@6.7.0 inspect-go-binary "<文件路径>" --format json
```
提取内嵌的 Go 编译器版本、模块依赖、构建设置。不需要安装 Go。
缺失记录 ≠ 不是 Go 二进制。

## PE 托管代码检查（.NET / CIL）
```powershell
npx -y rea-agents@6.7.0 inspect-managed-artifact "<文件路径>" --format json
```
检查 PE 文件是否包含 .NET CLI 元数据。不需要 CLR 加载目标程序集。

## Ghidra 驱动的 Native 分析（Windows 可用）
你电脑上已装好 Ghidra 12.1.4，以下命令直接可用：

```powershell
# 搜索字符串
npx -y rea-agents@6.7.0 search "<exe路径>" "关键词" --kind strings --provider ghidra --format json

# 搜索函数名
npx -y rea-agents@6.7.0 search "<exe路径>" "函数名" --kind procedures --provider ghidra --format json

# 反编译单个函数
npx -y rea-agents@6.7.0 function "<exe路径>" 0x401000 --provider ghidra --format json

# 保存分析快照（避免每次重新跑 Ghidra）
npx -y rea-agents@6.7.0 function "<exe路径>" main --snapshot "$env:TEMP\rea-snap" --provider ghidra --format json
```

**注意：**
- Ghidra 第一次启动 JVM 需要 1-2 分钟，耐心等
- 用 `--snapshot` 保存分析结果，后续命令复用
- Windows Ghidra 支持 x86 / x64 / ARM64 PE 文件

## 二进制布局（离线）
```powershell
# ⚠️ 仅支持 Linux x64 ELF（用 pwntools），Windows PE 不支持
npx -y rea-agents@6.7.0 inspect-binary-layout "<文件路径>" --format json
```

## SQLite 数据库
```powershell
# ⚠️ 需要 Node.js 24.15+，当前 Node 22.x 不可用
npx -y rea-agents@6.7.0 inspect-sqlite-database "<文件路径>" --format json
```

## Rust 二进制
```powershell
npx -y rea-agents@6.7.0 inspect-rust-binary "<文件路径>" --format json
```
检查嵌入的 cargo-auditable 依赖列表。

## PE 资源
```powershell
npx -y rea-agents@6.7.0 inspect-pe-resources "<文件路径>" --format json
```
查看 PE 文件的资源段（图标、版本信息、对话框等）。

## WASM 工件
```powershell
# ⚠️ 需要 WABT 工具
npx -y rea-agents@6.7.0 inspect-wasm-artifact "<文件路径>" --format json
```

## Mach-O 二进制
```powershell
# ⚠️ macOS 格式，Windows 上仅做基础解析
npx -y rea-agents@6.7.0 inspect-macho "<文件路径>" --format json
```

## EVM 字节码
```powershell
npx -y rea-agents@6.7.0 inspect-evm-interface "<hex字节码>" --format json
```
推断智能合约接口。不做链上查询。

## Electron 熔断配置
```powershell
npx -y rea-agents@6.7.0 inspect-electron-fuses "<exe路径>" --format json
```
检查 Electron 应用的熔断开关（是否允许 --inspect、nodeIntegration 等）。

## 地址转文件偏移
```powershell
# 把内存地址转成文件里的字节偏移
npx -y rea-agents@6.7.0 address-to-file-offset "<exe路径>" 0x140002910 --format json
```

## 提取归档内容
```powershell
# 安全提取归档里的所有常规文件
npx -y rea-agents@6.7.0 extract-artifact "<归档路径>" --format json
```

## .NET 元数据成员检查
```powershell
# 检查 PE/CLI 元数据成员、签名、CIL 锚点、字符串字面量
npx -y rea-agents@6.7.0 inspect-managed-members "<exe路径>" --format json
```

## 原生加载映像验证
```powershell
# 验证加载的原生字节、源码映射、重定位和入口点
npx -y rea-agents@6.7.0 inspect-native-load-image "<exe路径>" --format json
```

## 原生数据类型检查
```powershell
# 检查恢复的数据库类型或类型化数据对象
npx -y rea-agents@6.7.0 inspect-native-data-type "<exe路径>" --format json
```

## Obj-C/Swift 调度元数据
```powershell
# ⚠️ 主要用于 macOS Mach-O 文件
npx -y rea-agents@6.7.0 inspect-native-dispatch-metadata "<文件路径>" --format json
```

## 字节模式搜索
```powershell
# 搜索十六进制字节模式（支持 ?? 通配符）
npx -y rea-agents@6.7.0 search-bytes "<exe路径>" "48 8B ?? 20" --format json
```

## 函数注释编辑
```powershell
# 编辑函数注释并返回刷新后的分析
npx -y rea-agents@6.7.0 annotate-native-function "<exe路径>" 0x140002910 --format json
```

## 调用目标解析
```powershell
# 解析一个静态原生调用点的目标函数
npx -y rea-agents@6.7.0 resolve-native-call-targets "<exe路径>" 0x140002910 --format json
```

## 列出支持的架构
```powershell
# ⚠️ 主要用于 Mach-O 文件
npx -y rea-agents@6.7.0 list-architectures "<文件路径>" --format json
```

## Plist 元数据解析
```powershell
# ⚠️ 主要用于 macOS 应用
npx -y rea-agents@6.7.0 inspect-plist "<文件路径>" --format json
```

## 归档包清单
```powershell
npx -y rea-agents@6.7.0 inspect-artifact "<文件路径>" --format json
```
通用工件检查，自动识别 PE / ELF / Mach-O / ZIP / APK / IPA / DMG。
输出文件清单、哈希、格式分类，并给出下一步建议。

## 平台支持矩阵

| 功能 | Windows | Linux | macOS |
|------|---------|-------|-------|
| inspect-artifact | ✅ | ✅ | ✅ |
| inspect-managed-artifact | ✅ | ✅ | ✅ |
| inspect-go-binary | ✅ | ✅ | ✅ |
| inspect-rust-binary | ✅ | ✅ | ✅ |
| inspect-pe-resources | ✅ | ⚠️ | ⚠️ |
| inspect-macho | ⚠️ 基础 | ⚠️ 基础 | ✅ |
| inspect-electron-fuses | ✅ | ✅ | ✅ |
| Ghidra native 分析 | ✅ | ✅ | ✅ |
| inspect-binary-layout | ❌ | ✅ | ❌ |
| inspect-evm-interface | ❌ | ✅ | ❌ |
| inspect-sqlite-database | ⚠️ 需 Node 24+ | ⚠️ 需 Node 24+ | ⚠️ 需 Node 24+ |
| inspect-wasm-artifact | ⚠️ 需 WABT | ⚠️ 需 WABT | ⚠️ 需 WABT |
| Hopper | ❌ | ❌ | ✅ |
| JADX (Android) | 需手动配置 | 需手动配置 | 需手动配置 |
| 固件提取 (Binwalk) | ❌ | ✅ | ❌ |
