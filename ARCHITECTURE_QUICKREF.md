# Sentry 项目架构速查卡

## 项目概览
```
Sentry (anti.rusda)
├── UI: 底部 Tab + ViewPager2（3 页）
│   ├── 概览 (Overview)   - 设备信息 + 安全分数 + 一键扫描
│   ├── 调试检测 (Debug) - Frida/Xposed/ptrace/端口等
│   └── 环境检测 (Env)   - Root/Bootloader/模拟器等
│
├── Java Layer
│   ├── MainActivity / OverviewFragment / DebugFragment / EnvironmentFragment
│   ├── DebugDetectionManager  - 调试类检测（依赖 libantidebug.so）
│   ├── EnvDetectionManager   - 环境类检测（依赖 libenvdetect.so）
│   ├── DetectionManager      - 兼容入口，合并两类检测
│   └── DetectionResult      - 结果模型（含 score/maxScore）
│
├── Native Layer（两个 so）
│   ├── libantidebug.so  - 调试检测：thread/port/memory/hook/anti_debug + JNI(native-lib.cpp)
│   └── libenvdetect.so  - 环境检测：native-lib-env.cpp + env_detector + syscall_utils
│
└── Resources：2 种语言 (en/zh)，Material Design 3
```

## 文件位置速查

### Java 源码
| 类 | 路径 |
|----|------|
| MainActivity | `app/src/main/java/anti/rusda/MainActivity.java` |
| OverviewFragment | `app/src/main/java/anti/rusda/OverviewFragment.java` |
| DebugFragment | `app/src/main/java/anti/rusda/DebugFragment.java` |
| EnvironmentFragment | `app/src/main/java/anti/rusda/EnvironmentFragment.java` |
| SettingsActivity | `app/src/main/java/anti/rusda/SettingsActivity.java` |
| DebugDetectionManager | `app/src/main/java/anti/rusda/detector/DebugDetectionManager.java` |
| EnvDetectionManager | `app/src/main/java/anti/rusda/detector/EnvDetectionManager.java` |
| PlayIntegrityHelper | `app/src/main/java/anti/rusda/detector/PlayIntegrityHelper.java` |
| DeviceFingerprintCollector | `app/src/main/java/anti/rusda/detector/DeviceFingerprintCollector.java` |
| DetectionManager | `app/src/main/java/anti/rusda/detector/DetectionManager.java` |
| DetectionResult | `app/src/main/java/anti/rusda/detector/DetectionResult.java` |
| MainPagerAdapter | `app/src/main/java/anti/rusda/ui/MainPagerAdapter.java` |
| DetectionAdapter | `app/src/main/java/anti/rusda/ui/adapter/DetectionAdapter.java` |

### C++ 源码
| 模块 | 路径 |
|------|------|
| JNI 调试库 | `app/src/main/cpp/native-lib.cpp` |
| JNI 环境库 | `app/src/main/cpp/native-lib-env.cpp` |
| Thread Detector | `app/src/main/cpp/detector/thread_detector.cpp` |
| Port Scanner | `app/src/main/cpp/detector/port_scanner.cpp` |
| Memory Scanner | `app/src/main/cpp/detector/memory_scanner.cpp` |
| Hook Detector | `app/src/main/cpp/detector/hook_detector.cpp` |
| Anti Debug | `app/src/main/cpp/detector/anti_debug.cpp` |
| Syscall Utils | `app/src/main/cpp/utils/syscall_utils.cpp` |

### 资源文件
| 类型 | 路径 |
|------|------|
| 主布局 | `app/src/main/res/layout/activity_main.xml` (ViewPager2 + TabLayout) |
| 概览/调试/环境 | `fragment_overview.xml`, `fragment_debug.xml`, `fragment_environment.xml` |
| 设置布局 | `app/src/main/res/layout/activity_settings.xml` |
| 项布局 | `app/src/main/res/layout/item_detection.xml` |
| 英文字符串 | `app/src/main/res/values/strings.xml` |
| 中文字符串 | `app/src/main/res/values-zh/strings.xml` |
| 颜色定义 | `app/src/main/res/values/colors.xml` |
| 主题定义 | `app/src/main/res/values/themes.xml` |
| 夜间主题 | `app/src/main/res/values-night/themes.xml` |

### 构建配置
| 文件 | 路径 |
|------|------|
| 项目构建 | `build.gradle` |
| 模块构建 | `app/build.gradle` |
| CMake | `app/src/main/cpp/CMakeLists.txt` |
| 版本目录 | `gradle/libs.versions.toml` |
| ProGuard | `app/proguard-rules.pro` |
| 应用清单 | `app/src/main/AndroidManifest.xml` |

## 检测项清单（按 Tab 分）

**调试检测 (DebugDetectionManager, libantidebug.so)**  
| # | 检测项 | 检测目标 |
|---|--------|----------|
| 1 | Frida 线程 | gmain, gdbus, frida-agent... |
| 2 | Frida 端口 | 27042, 27043, 27044 (Native syscall) |
| 3 | 内存签名 | frida, gum-js, liblspd.so, libriru.so (Native syscall) |
| 4 | 命名管道 | /proc/self/net/unix |
| 5 | Ptrace/IDA 附加 | TracerPid |
| 6 | 调试器附加 | Debug.isDebuggerConnected() |
| 7 | Xposed/Hook | XposedBridge |

**环境检测 (EnvDetectionManager, libenvdetect.so)**  
| # | 检测项 | 检测目标 |
|---|--------|----------|
| 1 | Bootloader | ro.boot.* (含 warranty_bit, avb_version) |
| 2 | Magisk/Root | /data/adb/magisk, modules, Shamiko, zygisk_* 扫描, 包名 |
| 3 | LSPosed | /data/adb/lspd, zygisk_lsposed, HideMyApplist |
| 4 | Play Integrity | Google Play Integrity API，需服务端验证 |
| 5 | 可疑文件 | /data/adb/*, /data/local/tmp/frida* |
| 6 | 模拟器 | QEMU, BlueStacks, build 属性 |
| 7 | 内核补丁 | Build.VERSION.SECURITY_PATCH > 12/24 月 |
| 8 | ADB 调试 | adb_enabled, adb_wifi_enabled, 端口 5555 (Native) |
| 9 | 多实例 | dual/clone/parallel 路径 |
| 10 | 容器/虚拟化 | 包名与 cmdline, VirtualApp/太极/平行空间, cgroup (lxc/docker/kubepods) |

**辅助**：`DeviceFingerprintCollector` 采集 fingerprint、elapsedRealtime、/proc/version。

每项有 **分数**：NORMAL=满分，WARNING=半分的，DANGER=0；概览页显示总分百分比（0–100）。

## 状态颜色

```xml
STATUS_NORMAL  (0)  → #FF43A047 (绿色)
STATUS_WARNING (1)  → #FFFB8C00 (橙色)
STATUS_DANGER  (2)  → #FFE53935 (红色)
```

## 快速命令

```bash
# 构建Debug版本
./gradlew app:assembleDebug

# 构建Release版本
./gradlew app:assembleRelease

# 清理项目
./gradlew clean

# 安装到设备
./gradlew app:installDebug
```

## 扩展模板

### 添加新检测项

- **调试类**：在 `DebugDetectionManager.java` 增加方法并加入 `runAllDetections()`；若需 Native 则在 `native-lib.cpp` 增加 JNI。
- **环境类**：在 `EnvDetectionManager.java` 增加方法并加入 `runAllDetections()`；可选 `native-lib-env.cpp`。
- 使用 `DetectionResult(title, description, status)` 或带 `maxScore` 的构造；分数会参与概览页总分计算。

### 添加 JNI 接口

```cpp
// 调试检测 → native-lib.cpp，类名 DebugDetectionManager
Java_anti_rusda_detector_DebugDetectionManager_nativeXxx(...)

// 环境检测 → native-lib-env.cpp，类名 EnvDetectionManager
Java_anti_rusda_detector_EnvDetectionManager_nativeXxx(...)
```

### 添加字符串

```xml
<!-- values/strings.xml -->
<string name="detect_new_feature">New Feature</string>
<string name="detail_new_feature">Description here</string>

<!-- values-zh/strings.xml -->
<string name="detect_new_feature">新特性检测</string>
<string name="detail_new_feature">描述内容</string>
```

---
**版本**: v1.0.0 | **架构**: Java + C++ Hybrid | **UI**: Material Design 3
