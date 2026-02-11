# Sentry 项目架构速查卡

## 项目概览
```
Sentry (anti.rusda)
├── Java Layer (Presentation + Detection Engine)
│   ├── MainActivity          - 主界面/扫描控制
│   ├── SettingsActivity      - 设置界面
│   ├── DetectionManager      - 12种检测方法
│   └── DetectionResult       - 结果数据模型
│
├── Native Layer (C++)
│   ├── libantifrida.so       - 原生检测库
│   ├── thread_detector       - /proc/self/task扫描
│   ├── port_scanner          - TCP端口扫描
│   ├── memory_scanner        - /proc/self/maps分析
│   ├── hook_detector         - 内联Hook检测
│   ├── anti_debug            - 反调试检测
│   └── syscall_utils         - 直接系统调用
│
└── Resources
    ├── 2种语言 (en/zh)
    ├── 3个布局
    └── Material Design 3主题
```

## 文件位置速查

### Java 源码
| 类 | 路径 |
|----|------|
| MainActivity | `app/src/main/java/anti/rusda/MainActivity.java` |
| SettingsActivity | `app/src/main/java/anti/rusda/SettingsActivity.java` |
| SentryApp | `app/src/main/java/anti/rusda/SentryApp.java` |
| LocaleHelper | `app/src/main/java/anti/rusda/LocaleHelper.java` |
| DetectionManager | `app/src/main/java/anti/rusda/detector/DetectionManager.java` |
| DetectionResult | `app/src/main/java/anti/rusda/detector/DetectionResult.java` |
| DetectionAdapter | `app/src/main/java/anti/rusda/ui/adapter/DetectionAdapter.java` |

### C++ 源码
| 模块 | 路径 |
|------|------|
| JNI Bridge | `app/src/main/cpp/native-lib.cpp` |
| Thread Detector | `app/src/main/cpp/detector/thread_detector.cpp` |
| Port Scanner | `app/src/main/cpp/detector/port_scanner.cpp` |
| Memory Scanner | `app/src/main/cpp/detector/memory_scanner.cpp` |
| Hook Detector | `app/src/main/cpp/detector/hook_detector.cpp` |
| Anti Debug | `app/src/main/cpp/detector/anti_debug.cpp` |
| Syscall Utils | `app/src/main/cpp/utils/syscall_utils.cpp` |

### 资源文件
| 类型 | 路径 |
|------|------|
| 主布局 | `app/src/main/res/layout/activity_main.xml` |
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

## 12项检测清单

| # | 检测项 | 方法名 | 状态 | 检测目标 |
|---|--------|--------|------|----------|
| 1 | Frida线程 | `detectFridaThreads()` | 🔴 | gmain, gdbus, frida-agent... |
| 2 | Frida端口 | `detectFridaPorts()` | 🔴 | 27042, 27043, 27044 |
| 3 | 内存签名 | `detectMemorySignatures()` | 🔴 | frida, gum-js, gthread |
| 4 | 命名管道 | `detectNamedPipes()` | 🔴 | /proc/self/net/unix |
| 5 | 调试模式 | `detectDebugMode()` | 🟡 | Debug.isDebuggerConnected() |
| 6 | Root检测 | `detectRoot()` | 🟡 | su, Magisk |
| 7 | 可疑文件 | `detectSuspiciousFiles()` | 🔴 | /data/local/tmp/frida* |
| 8 | Ptrace | `detectPtraceStatus()` | 🔴 | TracerPid |
| 9 | 模拟器 | `detectEmulator()` | 🟡 | QEMU, BlueStacks |
| 10 | SELinux | `detectSELinuxStatus()` | 🟡 | enforce/permissive |
| 11 | 库完整性 | `checkLibraryIntegrity()` | 🔴 | Xposed框架 |
| 12 | 多实例 | `checkProcessStatus()` | 🟡 | dual/clone/parallel |

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

```java
// DetectionManager.java
private DetectionResult detectNewFeature() {
    List<String> findings = new ArrayList<>();
    int status = DetectionResult.STATUS_NORMAL;

    // 检测逻辑...

    DetectionResult result = new DetectionResult(
        "New Feature Detection",
        findings.isEmpty() ? "Clean" : "Detected",
        status
    );
    result.setDetails(findings);
    return result;
}
```

### 添加JNI接口

```cpp
// native-lib.cpp
extern "C" JNIEXPORT jboolean JNICALL
Java_anti_rusda_MainActivity_nativeDetectNewFeature(JNIEnv* env, jobject thiz) {
    return detect_new_feature();
}
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
