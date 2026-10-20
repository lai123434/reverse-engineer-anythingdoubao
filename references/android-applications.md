# Android APK Analysis — CLI 版

## 前置条件
Android 分析需要：
- Java 17+（已装：JDK 21.0.12）
- JADX MCP JAR 0.7.1（⚠️ 未配置，需要手动设置 `REA_JADX_MCP_JAR` 环境变量）

REA 不会自动下载安装 JADX。如果没配置，降级到基础解压分析。

## 基础分析
```powershell
npx -y rea-agents@6.7.0 inspect-android-package "<apk路径>" --format json
```
输出包名、Manifest 声明、权限、组件清单。

## 类与方法分析（需要 JADX）
```powershell
# 搜索类
npx -y rea-agents@6.7.0 search-android-classes "<apk路径>" "LoginActivity" --format json

# 查看类成员（className 是位置参数）
npx -y rea-agents@6.7.0 inspect-android-class "<apk路径>" "com.example.LoginActivity" --format json

# 反编译方法
npx -y rea-agents@6.7.0 inspect-android-method "<apk路径>" "com.example.LoginActivity" "onCreate" --format json
```

## 降级方案（无 JADX 时）
把 APK 当 ZIP 解压，手动看：
```powershell
# 解压 APK
Expand-Archive "app.apk" -DestinationPath "C:\temp\apk-extracted"

# 看 AndroidManifest.xml（二进制格式，需要 apktool 或 aapt）
# 看 classes.dex（静态字符串搜索）
```

## 边界说明
- Manifest 和反编译代码都是**静态观察**，不等于运行时行为
- 传入引用是静态恢复的关系；反射、动态加载、未解析调用都是未知
- APK 不会被启动，不需要模拟器
