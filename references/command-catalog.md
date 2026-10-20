# REA CLI 完整命令目录（153 个命令）

按功能分类。标注 ✅ 已验证参数格式 / ⚠️ 需特定环境 / ❌ Windows 不可用。

---

## 🔍 基础检查（无需 Ghidra）

| 命令 | 说明 | Windows |
|------|------|---------|
| `inspect-artifact <path>` | 通用工件清单（自动识别格式） | ✅ |
| `inspect-managed-artifact <path>` | .NET / CIL 托管代码检查 | ✅ |
| `inspect-go-binary <path>` | Go 二进制元数据 | ✅ |
| `inspect-rust-binary <path>` | Rust cargo-auditable 依赖列表 | ✅ |
| `inspect-pe-resources <path>` | PE 资源段（图标/版本/对话框） | ✅ |
| `inspect-macho <path>` | Mach-O 二进制（基础解析） | ⚠️ 仅基础 |
| `inspect-electron-fuses <exe>` | Electron 熔断配置 | ✅ |
| `inspect-evidence-bundle <path>` | 证据包检查 | ✅ |
| `inspect-keyed-archive <path>` | 加密归档检查 | ✅ |
| `inspect-plist <path>` | macOS plist 文件 | ⚠️ |
| `inspect-signature <path>` | 文件签名检查 | ✅ |
| `inspect-pcap-capture <file>` | PCAP 抓包文件 | ⚠️ |
| `inspect-packet-capture <file>` | 网络抓包 | ⚠️ |
| `inspect-packet-fields <file>` | 抓包字段解析 | ⚠️ |

## 🔨 Ghidra Native 分析（需 Ghidra）

| 命令 | 说明 |
|------|------|
| `search <path> "关键词" --kind strings --provider ghidra` | 字符串搜索 |
| `search <path> "关键词" --kind procedures --provider ghidra` | 函数搜索 |
| `decompile <path> <地址> --provider ghidra` | 伪代码反编译 |
| `function <path> <地址> --provider ghidra` | 完整函数 dossier |
| `trace <path> "关键词" --provider ghidra` | 特性追踪 |
| `xrefs <path> <地址> --provider ghidra` | 交叉引用 |
| `inspect-native-api <path> <地址>` | 原生函数 API 边界 |
| `inspect-native-data-type <path>` | 数据类型检查 |
| `inspect-native-instruction <path> <地址>` | 单条指令解码 |
| `inspect-native-load-image <path>` | 加载映像验证 |
| `inspect-native-dispatch-metadata <path>` | Obj-C/Swift 调度元数据 |
| `inspect-native-ui-scenario` | 原生 UI 场景观察 |
| `observe-native-calls` | 原生调用观察 |
| `observe-native-ui` | 原生 UI 观察 |
| `observe-native-ui-action` | UI 动作追踪 |
| `trace-native-values <path> <procedure>` | 原生 def-use 追踪 |
| `resolve-native-call-targets` | 调用目标解析 |
| `annotate-native-function` | 函数注释 |
| `address-to-file-offset` | 地址转文件偏移 |
| `read-bytes <path> <offset> <length>` | 读取字节 |
| `search-bytes <path> <pattern>` | 字节模式搜索 |
| `instructions <path>` | 指令列表 |

## 📦 JS / Electron / Web 应用

| 命令 | 说明 | Windows |
|------|------|---------|
| `analyze-javascript-application <path>` | JS/Electron 静态分析 | ✅ |
| `analyze-web-bundle <path>` | Web bundle 分析 | ✅ |
| `recover-javascript-sources <asar> <输出目录>` | 恢复混淆 JS 源码 | ❌ Linux only |
| `trace-application-feature <request.json>` | 特性追踪（inputJson） | ✅ |
| `trace-javascript-semantics <request.json>` | JS 语义追踪 | ⚠️ |
| `trace-web-module-imports` | Web 模块导入追踪 | ⚠️ |
| `trace-web-source-location` | Web 源码位置追踪 | ⚠️ |
| `compare-application-versions <request.json>` | 版本对比（inputJson） | ✅ |
| `compare-javascript-export-shapes` | JS 导出形状对比 | ⚠️ |
| `compare-web-captures <before.json> <after.json>` | Web 抓包对比 | ⚠️ |
| `compare-source-to-bundle` | 源码 vs bundle 对比 | ⚠️ |
| `reconcile-javascript-runtime` | JS 运行时对账 | ⚠️ |
| `observe-javascript-runtime` | JS 运行时观察 | ⚠️ |
| `list-javascript-runtime-targets` | JS 运行时目标列表 | ⚠️ |
| `export-web-scripts` | 导出 Web 脚本 | ⚠️ |
| `inspect-web-page <url>` | Web 页面检查 | ⚠️ |
| `inspect-web-event-listeners` | Web 事件监听器 | ⚠️ |
| `inspect-web-network-capture <file> <format>` | Web 网络抓包 | ⚠️ |
| `discover-webmcp-tools` | WebMCP 工具发现 | ⚠️ |
| `capture-web-screenshot` | Web 截图 | ⚠️ |
| `compare-web-screenshots` | Web 截图对比 | ⚠️ |

## 📱 Android（ADB / JADX）

| 命令 | 说明 |
|------|------|
| `inspect-android-package <apk>` | APK 基本信息 |
| `search-android-classes <apk> "类名"` | 搜索类 |
| `inspect-android-class <apk> "完整类名"` | 类成员查看 |
| `inspect-android-method <apk> "类名" "方法名"` | 方法反编译 |
| `trace-android-references` | 类引用追踪 |
| `decode-android-resources` | Android 资源解码 |
| `inspect-adb-client` | ADB 客户端 |
| `inspect-adb-device` | ADB 设备 |
| `inspect-adb-display` | ADB 显示 |
| `inspect-adb-package` | ADB 包管理 |
| `inspect-adb-window` | ADB 窗口 |
| `list-adb-devices` | 列出 ADB 设备 |
| `list-adb-packages` | 列出 ADB 包 |
| `list-adb-processes` | 列出 ADB 进程 |
| `list-adb-services` | 列出 ADB 服务 |
| `list-adb-directory` | 列出 ADB 目录 |
| `list-adb-features` | ADB 功能列表 |
| `pull-adb-file` | 拉取 ADB 文件 |
| `pull-adb-package` | 拉取 ADB 包 |
| `push-adb-file` | 推送 ADB 文件 |
| `install-adb-package` | 安装 ADB 包 |
| `uninstall-adb-package` | 卸载 ADB 包 |
| `start-adb-activity` | 启动 ADB Activity |
| `start-adb-app` | 启动 ADB 应用 |
| `stop-adb-app` | 停止 ADB 应用 |
| `read-adb-logcat` | 读取 ADB logcat |
| `read-adb-setting` | 读取 ADB 设置 |
| `resolve-adb-packages` | 解析 ADB 包 |
| `collect-adb-bugreport` | 收集 ADB bugreport |
| `capture-adb-screen` | ADB 截屏 |
| `project-android-application-graph` | Android 应用图 |

## 🧊 特殊格式

| 命令 | 说明 | Windows |
|------|------|---------|
| `inspect-binary-layout <path>` | ELF 二进制布局 | ❌ Linux only |
| `inspect-evm-interface <hex> hex` | EVM 字节码分析 | ❌ Linux only |
| `inspect-sqlite-database <path>` | SQLite 数据库 | ⚠️ 需 Node 24+ |
| `inspect-wasm-artifact <path>` | WASM 工件 | ⚠️ 需 WABT |
| `inspect-firmware-regions <path>` | 固件区域识别 | ❌ Linux only |
| `extract-firmware <镜像> <输出目录>` | 固件提取 | ❌ Linux only |
| `inspect-dart-aot <path>` | Dart AOT 快照 | ⚠️ |
| `identify-flutter-build <path>` | Flutter 构建识别 | ⚠️ |
| `demangle-swift <path>` | Swift 符号 demangle | ⚠️ |
| `decode-interface-builder` | Interface Builder 解码 | ⚠️ |
| `decode-signal-recording` | Signal 录音解码 | ⚠️ |
| `inspect-signal-decoders` | Signal 解码器 | ⚠️ |
| `inspect-asset-catalog` | 资源目录检查 | ⚠️ |

## 🔧 调试与动态分析

| 命令 | 说明 |
|------|------|
| `debug-with-gdb` | GDB 调试 |
| `debug-with-rizin` | Rizin 调试 |
| `execute-rizin-command` | Rizin 命令执行 |
| `cutter-command` | Cutter 命令 |
| `list-cutter-sessions` | Cutter 会话列表 |
| `instrument-with-frida` | Frida instrumentation |
| `list-frida-devices` | Frida 设备列表 |
| `list-frida-processes` | Frida 进程列表 |
| `capture-process` | 进程捕获 |
| `compare-process-captures` | 进程捕获对比 |
| `kuna-*` | Kuna 分析引擎（需设置 REA_KUNA_COMMAND） |

## 📋 证据与工作流

| 命令 | 说明 |
|------|------|
| `inspect-analysis-view <request.json>` | 证据摘要视图（inline） |
| `evidence-export` | 证据导出 |
| `evidence-import` | 证据导入 |
| `compare <path>` | 通用对比 |
| `inspect <path>` | 通用检查 |
| `analyze <path>` | 通用分析 |
| `extract-artifact <path>` | 工件提取 |
| `setup` | 环境设置 |
| `update` | 更新 |
| `doctor` | 环境诊断 |
| `providers` | 列出 provider |
| `capabilities` | 列出能力 |
| `list-architectures` | 列出架构 |
| `list-objdump-architectures` | ObjDump 架构列表 |
| `instructions` | 指令列表 |

## 🖥️ Electron / 浏览器运行时

| 命令 | 说明 |
|------|------|
| `list-browser-targets` | 浏览器目标列表 |
| `list-electron-targets` | Electron 目标列表 |
| `capture-browser-scenario` | 浏览器场景捕获 |
| `capture-electron-scenario` | Electron 场景捕获 |
| `observe-web-session` | Web 会话观察 |
| `observe-web-execution` | Web 执行观察 |
| `inspect-electron-page` | Electron 页面检查 |

## 🍎 Apple 生态

| 命令 | 说明 |
|------|------|
| `project-apple-application-graph` | Apple 应用图 |
| `project-managed-application-graph` | 托管应用图 |
| `project-harmony-application-graph` | 鸿蒙应用图 |
| `import-managed-reconstruction` | 托管重建导入 |
| `import-reference-source` | 参考源码导入 |
| `inspect-managed-members` | 托管成员检查 |
| `inspect-managed-native-boundaries` | 托管-原生边界 |
| `compare-managed-members` | 托管成员对比 |
| `verify-managed-native-boundaries` | 托管边界验证 |

## 🧪 其他

| 命令 | 说明 |
|------|------|
| `compare-wasm-interfaces` | WASM 接口对比 |
| `inspect-recorded-crash` | 记录崩溃检查 |
| `inspect-jeb-client` | JEB 客户端 |
| `open-jeb-project` | JEB 项目打开 |
| `list-jeb-units` | JEB 单元列表 |
| `decompile-jeb-item` | JEB 反编译 |
| `inspect-apktool-client` | Apktool 客户端 |
| `compare-javascript-export-shapes` | JS 导出形状对比 |
| `build-reconstruction-obligation-ledger` | 重建义务台账 |
| `evaluate-reconstruction-coverage` | 重建覆盖率评估 |

---

**统计：共 155 个命令**

**标注说明：**
- ✅ 已验证参数格式，Windows 可用
- ⚠️ 需要特定环境/工具，或仅基础功能
- ❌ Windows 不可用，仅 Linux/macOS
