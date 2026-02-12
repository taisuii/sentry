---
name: sentry-project-structure
description: Documents the Sentry Android security detection app structure (Java + C++ hybrid, anti-Frida). Use before modifying the codebase, adding features, or performing maintenance to understand layout, key paths, and conventions.
---

# Sentry 项目结构

Android 安全检测应用，Java + Native (C++) 双引擎，包名 `anti.rusda`。**两个 Native 库**：`libantidebug.so`（调试检测）、`libenvdetect.so`（环境检测）。主界面为 **3 个 Tab**：概览（设备信息+分数）、调试检测、环境检测。调试检测现为 **9 项**，含 **Maps 二次检测 (Java exec)**（`Runtime.exec("cat /proc/pid/maps")` 与 Native syscall 双通道）、**Dirty Page / Memory Injection**（脏页/内存注入：Smaps Private_Dirty + VMap + Pagemap bit 55，实现位于 libenvdetect，由 DebugDetectionManager 加载 envdetect 后调用）。环境检测含 **Bootloader**（Native 系统属性 + Key Attestation TEE RootOfTrust）、**Dangerous Apps**（多渠道：meta-data、APK assets/xposed_init、modules.list，warnOnly）。**LSPosed Hook** 已合并至调试检测的 Xposed / Hook Framework。

## 目录树

```
sentry/
├── app/
│   ├── build.gradle              # 模块构建、NDK、CMake 入口
│   ├── proguard-rules.pro
│   └── src/main/
│       ├── AndroidManifest.xml   # SentryApp, MainActivity, SettingsActivity
│       ├── cpp/
│       │   ├── CMakeLists.txt    # 构建 libantidebug + libenvdetect，arm64-v8a，16KB 对齐
│       │   ├── native-lib.cpp    # JNI 桥接（调试检测 → DebugDetectionManager）
│       │   ├── native-lib-env.cpp # JNI 桥接（环境检测库桩）
│       │   ├── detector/         # 调试检测器 + 环境检测器
│       │   │   ├── thread_detector.cpp/h
│       │   │   ├── port_scanner.cpp/h
│       │   │   ├── memory_scanner.cpp/h
│       │   │   ├── hook_detector.cpp/h
│       │   │   ├── xposed_detector.cpp/h
│       │   │   ├── anti_debug.cpp/h
│       │   │   └── env_detector.cpp/h
│       │   └── utils/
│       │       └── syscall_utils.cpp/h
│       ├── java/anti/rusda/
│       │   ├── BaseActivity.java
│       │   ├── MainActivity.java       # ViewPager2 + 底部 Tab，协调扫描
│       │   ├── OverviewFragment.java   # 概览：设备信息 + 安全分数
│       │   ├── DebugFragment.java      # 调试检测列表
│       │   ├── EnvironmentFragment.java # 环境检测列表
│       │   ├── SettingsActivity.java
│       │   ├── SentryApp.java
│       │   ├── LocaleHelper.java
│       │   ├── detector/
│       │   │   ├── DetectionManager.java       # 兼容入口，委托 Debug + Env
│       │   │   ├── DebugDetectionManager.java # 调试检测（Frida/Xposed/LSPosed/ptrace 等）
│       │   │   ├── EnvDetectionManager.java   # 环境检测（Magisk/Bootloader/Play Integrity/模拟器等）
│       │   │   ├── DetectionResult.java       # 结果模型 (title, status, details, score)
│       │   │   ├── KeyAttestationHelper.java   # Key Attestation（供 Bootloader 调用）
│       │   │   └── DeviceFingerprintCollector.java # 设备指纹采集
│       │   └── ui/
│       │       ├── MainPagerAdapter.java
│       │       └── adapter/DetectionAdapter.java
│       └── res/
│           ├── layout/   # activity_main(ViewPager2+Tab), fragment_overview/debug/environment, item_detection
│           ├── menu/     # top_app_bar.xml
│           ├── values/   # strings.xml, colors.xml, themes.xml
│           ├── values-zh/
│           ├── values-night/
│           ├── drawable/
│           ├── mipmap-*/
│           └── xml/
├── gradle/
├── build.gradle
├── settings.gradle
└── doc/
    └── DETECTION_SPEC.md   # 检测规范（检测项、评分、实现、文件速查）
```

## 关键路径速查

| 用途 | 路径 |
|------|------|
| 主界面 / Tab | `app/src/main/java/anti/rusda/MainActivity.java` |
| 概览 Fragment | `app/src/main/java/anti/rusda/OverviewFragment.java` |
| 调试/环境 Fragment | `app/src/main/java/anti/rusda/DebugFragment.java`, `EnvironmentFragment.java` |
| 设置 | `app/src/main/java/anti/rusda/SettingsActivity.java` |
| 调试检测引擎 | `app/src/main/java/anti/rusda/detector/DebugDetectionManager.java` |
| 环境检测引擎 | `app/src/main/java/anti/rusda/detector/EnvDetectionManager.java` |
| 结果模型 | `app/src/main/java/anti/rusda/detector/DetectionResult.java` |
| 列表适配器 | `app/src/main/java/anti/rusda/ui/adapter/DetectionAdapter.java` |
| JNI 调试库 | `app/src/main/cpp/native-lib.cpp` |
| JNI 环境库 | `app/src/main/cpp/native-lib-env.cpp` |
| 原生构建 | `app/src/main/cpp/CMakeLists.txt` |
| 主布局 | `app/src/main/res/layout/activity_main.xml` |
| 字符串 (en/zh) | `app/src/main/res/values/strings.xml`, `values-zh/strings.xml` |
| 依赖版本 | `gradle/libs.versions.toml` |
| 检测规范文档 | `doc/DETECTION_SPEC.md` |

## 技术要点

- **命名空间/包名**: `anti.rusda`；**applicationId**: `anti.rusda`
- **Native 库**: `libantidebug.so`（调试检测）、`libenvdetect.so`（环境检测）
- **JNI 约定**: 调试 → `nativeDetectFridaThreads`、`nativeGetFridaPortScanResult`（端口 + frida-server + Frida 进程如 re.frida.helper）、`nativeGetMemorySignatureResult`、`nativeDetectXposedPaths`、`nativeDetectHook`、`nativeDetectZygiskInjection`（实现于 libenvdetect，Debug 加载 envdetect 后调用）等；环境 → `nativeDetectMagisk`、`nativeDetectBootloader`、`nativeDetectSuspiciousFiles`、`nativeDetectEmulator`、`nativeCheckPort`、`nativeDetectAdb`、`nativeCheckCgroup`、`nativeGetEnvVersion`；Bootloader 含 Native + Java `KeyAttestationHelper.runAttestationSync()`；**Dangerous Apps** 为 Java + Native 混合（`nativeVerifyXposedModules`：APK assets/xposed_init、modules.list）；**ADB Debug** 为 `nativeDetectAdb`（端口/net/tcp/adbd/sysfs）+ Java Settings + exec 替代路径；指纹 → `nativeGetProcVersion`
- **检测状态**: `STATUS_NORMAL=0`(绿), `STATUS_WARNING=1`(橙), `STATUS_DANGER=2`(红)；每项有 **分数**（getEarnedScore/getMaxScore），概览页显示总分百分比
- **ABI**: 仅 `arm64-v8a`；C++17；Android 15+ 使用 16KB 页面对齐
- **导航**: 底部 TabLayout + ViewPager2 左右滑动，三页：概览、调试检测、环境检测

## 扩展时需同步修改的位置

- **新增调试检测项**: `DebugDetectionManager.java` → 可选 `cpp/detector/` → `native-lib.cpp` JNI
- **新增环境检测项**: `EnvDetectionManager.java` → `cpp/detector/env_detector.cpp` → `native-lib-env.cpp` JNI
- **检测开发规范**：新增检测时参见 `.cursor/rules/detection-development.mdc`（Native 优先、syscall、评分与误报控制）
- **新增 Activity/Fragment**: `AndroidManifest.xml`、对应 Java、布局 `res/layout/`
- **新增资源/语言**: `res/values*/`、`values-<locale>/strings.xml`
- **变更 Native 源**: `app/src/main/cpp/CMakeLists.txt` 的 `add_library` 列表

## 详细文档

- **检测规范**（18 项检测说明、评分机制、实现层、误报控制、文件速查）：见 [doc/DETECTION_SPEC.md](../../../doc/DETECTION_SPEC.md)
- 项目根目录暂无 `PROJECT_ARCHITECTURE.md` / `ARCHITECTURE_QUICKREF.md`，以本 SKILL 与 `doc/DETECTION_SPEC.md` 为准

## 何时更新本 Skill

在以下情况发生后应更新本 SKILL.md（以及必要时 PROJECT_ARCHITECTURE.md / ARCHITECTURE_QUICKREF.md）：

- 新增或删除模块、包、重要类或 C++ 检测器
- 目录层级或关键路径变更
- 新增/删除检测项或入口（如新 Activity）
- 构建方式变更（如 CMake 源列表、新 ABI、Gradle 模块）

保持「目录树」与「关键路径速查」与仓库实际结构一致，便于 Agent 正确执行修改与维护。
