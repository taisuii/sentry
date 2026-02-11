# Sentry - Android Security Detection Framework

## 项目概述

**Sentry** 是一款专业的 Android 环境安全检测应用，采用 **Java + C++ 双引擎架构**，专门用于检测 Frida 动态插桩工具、调试器、Root 环境、模拟器等潜在威胁。

### 核心特性
- **双引擎检测**: Java 层快速检测 + Native 层深度检测
- **反 Hook 设计**: 直接系统调用，绕过 libc hook
- **Material Design 3**: 现代化 UI，支持浅色/深色主题
- **国际化**: 英文/简体中文双语支持
- **Android 15+ 兼容**: 16KB 页面对齐支持

---

## 架构图

```
┌─────────────────────────────────────────────────────────────┐
│                      PRESENTATION LAYER                      │
│  ┌─────────────────┐  ┌─────────────────┐                   │
│  │  MainActivity   │  │ SettingsActivity│                   │
│  │  (扫描/结果展示) │  │ (主题/语言设置)  │                   │
│  └────────┬────────┘  └─────────────────┘                   │
│           │                                                  │
│  ┌────────▼────────┐  ┌─────────────────┐                   │
│  │ DetectionAdapter│  │   LocaleHelper  │                   │
│  │ (RecyclerView)  │  │   (语言切换)     │                   │
│  └─────────────────┘  └─────────────────┘                   │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                     DETECTION ENGINE                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              DetectionManager                       │   │
│  │  (Java层 - 12种检测方法的统一入口)                   │   │
│  └─────────────────────────────────────────────────────┘   │
│           │                                                  │
│  ┌────────▼────────┐  ┌───────────────┐  ┌───────────────┐ │
│  │ DetectionResult │  │  Thread Check │  │   Port Scan   │ │
│  │   (结果模型)     │  │   Root Check  │  │  Memory Scan  │ │
│  └─────────────────┘  │   Debug Check │  │  Emulator Chk │ │
│                       │   File Check  │  │   SELinux Chk │ │
│                       └───────────────┘  └───────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │ JNI
┌─────────────────────────────────────────────────────────────┐
│                    NATIVE LAYER (C++)                        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  libantifrida.so (ARM64-v8a, 16KB对齐)              │   │
│  └─────────────────────────────────────────────────────┘   │
│           │                                                  │
│  ┌────────▼────────┐  ┌───────────────┐  ┌───────────────┐ │
│  │  thread_detector│  │  port_scanner │  │ memory_scanner│ │
│  │  hook_detector  │  │  anti_debug   │  │ syscall_utils │ │
│  └─────────────────┘  └───────────────┘  └───────────────┘ │
│                                                              │
│  直接系统调用 (syscall) 绕过 libc hook                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 模块详细说明

### 1. Presentation Layer (表现层)

#### 1.1 MainActivity
**路径**: `app/src/main/java/anti/rusda/MainActivity.java`

**职责**:
- 加载原生库 `libantifrida.so`
- 初始化检测引擎 `DetectionManager`
- 管理扫描状态和结果展示
- 处理筛选 Chip 交互

**关键方法**:
```java
public native boolean nativeDetectFridaThread();
public native boolean nativeDetectFridaPort();
public native boolean nativeDetectFridaMemory();
public native boolean nativeDetectDebugMode();
public native boolean nativeDetectHook();
public native String nativeGetDetectionDetails();
```

**UI 组件**:
- MaterialToolbar (顶部设置按钮)
- MaterialCardView (状态总览)
- LinearProgressIndicator (扫描进度)
- ChipGroup (筛选: 全部/失败/警告/通过)
- RecyclerView (检测结果列表)

#### 1.2 SettingsActivity
**路径**: `app/src/main/java/anti/rusda/SettingsActivity.java`

**功能**:
- 主题切换 (跟随系统/浅色/深色)
- 语言切换 (English/简体中文)
- 自动扫描开关
- 高级检测开关

#### 1.3 LocaleHelper
**路径**: `app/src/main/java/anti/rusda/LocaleHelper.java`

**职责**:
- 语言偏好持久化 (SharedPreferences)
- Context 语言环境配置
- 支持 Android N+ 的语言配置

---

### 2. Detection Engine (检测引擎层)

#### 2.1 DetectionManager
**路径**: `app/src/main/java/anti/rusda/detector/DetectionManager.java`

**12 种检测方法**:

| # | 检测项 | 方法 | 状态 | 说明 |
|---|--------|------|------|------|
| 1 | Frida 线程检测 | `detectFridaThreads()` | DANGER | 扫描 `/proc/self/task` 目录，检测 gmain/gdbus/frida-agent 等线程名 |
| 2 | Frida 端口检测 | `detectFridaPorts()` | DANGER | 扫描 127.0.0.1:27042/27043/27044 |
| 3 | 内存签名检测 | `detectMemorySignatures()` | DANGER | 分析 `/proc/self/maps`，查找 frida/gum-js/gthread 等签名 |
| 4 | 命名管道检测 | `detectNamedPipes()` | DANGER | 检查 `/proc/self/net/unix` 中的 Frida 相关管道 |
| 5 | 调试模式检测 | `detectDebugMode()` | WARNING | 检查 `Debug.isDebuggerConnected()` 和 `FLAG_DEBUGGABLE` |
| 6 | Root 检测 | `detectRoot()` | WARNING | 检查 su 二进制文件、Magisk 目录 |
| 7 | 可疑文件检测 | `detectSuspiciousFiles()` | DANGER | 检查 `/data/local/tmp/frida*` 等路径 |
| 8 | Ptrace 状态检测 | `detectPtraceStatus()` | DANGER | 检查 `/proc/self/status` 中的 TracerPid |
| 9 | 模拟器检测 | `detectEmulator()` | WARNING | 检查硬件属性、QEMU 文件、BlueStacks/Nox 指示器 |
| 10 | SELinux 状态 | `detectSELinuxStatus()` | WARNING | 检查 `/sys/fs/selinux/enforce` 是否为宽容模式 |
| 11 | 库完整性检查 | `checkLibraryIntegrity()` | DANGER | 检查 Xposed 框架是否存在 |
| 12 | 多实例检测 | `checkProcessStatus()` | WARNING | 检查包名和数据目录是否包含 dual/clone/parallel 等关键词 |

**状态定义**:
```java
public static final int STATUS_NORMAL = 0;   // 绿色 - 通过
public static final int STATUS_WARNING = 1;  // 橙色 - 警告
public static final int STATUS_DANGER = 2;   // 红色 - 危险
```

#### 2.2 DetectionResult
**路径**: `app/src/main/java/anti/rusda/detector/DetectionResult.java`

**数据模型**:
```java
public class DetectionResult {
    private String title;           // 检测项名称
    private String description;     // 简短描述
    private int status;             // 状态 (0/1/2)
    private List<String> details;   // 详细结果列表
    private boolean expanded;       // 是否展开
}
```

---

### 3. Native Layer (原生层 C++)

#### 3.1 模块结构

```
app/src/main/cpp/
├── CMakeLists.txt              # CMake 构建配置
├── native-lib.cpp              # JNI 接口层
├── detector/
│   ├── thread_detector.cpp/h   # 线程检测
│   ├── port_scanner.cpp/h      # 端口扫描
│   ├── memory_scanner.cpp/h    # 内存签名扫描
│   ├── hook_detector.cpp/h     # Hook 检测
│   └── anti_debug.cpp/h        # 反调试
└── utils/
    ├── syscall_utils.cpp/h     # 系统调用工具
    └── custom_string.h         # 自定义字符串处理
```

#### 3.2 thread_detector
**功能**: 扫描进程线程检测 Frida

```cpp
// 检测关键词
const char* FRIDA_THREADS[] = {
    "gmain", "gdbus", "pool-spawner", "frida-agent",
    "frida-gadget", "frida", "gum-js-loop", "gthread"
};

// 扫描路径: /proc/self/task/[tid]/comm
```

#### 3.3 port_scanner
**功能**: 扫描 Frida 默认端口

```cpp
// 检测端口
const int FRIDA_PORTS[] = {27042, 27043, 27044};

// 方法: 尝试 connect() 到 127.0.0.1:port
```

#### 3.4 memory_scanner
**功能**: 扫描内存映射

```cpp
// 扫描路径: /proc/self/maps
// 检测签名: frida, FRIDA, gum-js, gthread, gobject
```

#### 3.5 hook_detector
**功能**: 检测函数 Hook

```cpp
// ARM64 内联 Hook 检测 (分支指令)
// 检查函数前几条指令是否为:
// - b/bl (分支)
// - br/blr (寄存器分支)
// - 异常生成指令

// PLT/GOT 表完整性检查
```

#### 3.6 anti_debug
**功能**: 反调试检测

```cpp
// 检测方法:
// 1. TracerPid 检查 (/proc/self/status)
// 2. 调试状态寄存器 (ARM: MDSCR_EL1)
// 3. 父进程检查 (是否为调试器)
// 4. 环境变量检查 (LD_PRELOAD, LD_DEBUG)
```

#### 3.7 syscall_utils
**功能**: 直接系统调用

```cpp
// 绕过 libc hook 的直接系统调用
// 支持架构: ARM64, ARM32, x86, x86_64

// 自定义实现:
sys_open()   // 代替 open()
sys_read()   // 代替 read()
sys_write()  // 代替 write()
sys_close()  // 代替 close()

// 自定义字符串函数:
my_strlen(), my_strcmp(), my_strcpy()
my_memset(), my_memcpy()
```

---

### 4. Resource Layer (资源层)

#### 4.1 布局文件

| 文件 | 用途 |
|------|------|
| `activity_main.xml` | 主界面: CoordinatorLayout + AppBar + RecyclerView |
| `activity_settings.xml` | 设置界面: 主题/语言/开关 |
| `item_detection.xml` | 检测项卡片: MaterialCardView |

#### 4.2 主题配色

**主色调** (Material Design 3):
```xml
<!-- Indigo 主色 -->
<color name="sentry_primary">#FF3F51B5</color>

<!-- Blue Grey 次色 -->
<color name="sentry_secondary">#FF546E7A</color>

<!-- Teal 强调色 -->
<color name="sentry_tertiary">#FF00897B</color>

<!-- 状态色 -->
<color name="status_healthy">#FF43A047</color>
<color name="status_warning">#FFFB8C00</color>
<color name="status_danger">#FFE53935</color>
```

#### 4.3 国际化

| 文件 | 语言 |
|------|------|
| `values/strings.xml` | English (默认) |
| `values-zh/strings.xml` | 简体中文 |

---

## 技术栈

### Android 框架
- **minSdk**: 24 (Android 7.0)
- **targetSdk**: 36 (Android 16)
- **compileSdk**: 36
- **架构**: arm64-v8a (主要)

### UI 框架
- **Material Design 3**: `com.google.android.material:material:1.12.0`
- **AppCompat**: `androidx.appcompat:appcompat:1.7.0`
- **RecyclerView**: 结果列表
- **CardView**: 卡片设计
- **CoordinatorLayout**: 协调布局

### 原生开发
- **CMake**: 3.22.1
- **NDK**: 支持 arm64-v8a
- **C++标准**: C++17
- **16KB对齐**: `-Wl,-z,max-page-size=16384`

### 构建工具
- **Android Gradle Plugin**: 8.13.1
- **Gradle**: 8.13
- **ProGuard**: 代码混淆 (release)

---

## 构建配置

### 模块级 build.gradle 关键配置

```gradle
android {
    namespace 'anti.rusda'
    compileSdk 36

    defaultConfig {
        applicationId "anti.rusda"
        minSdk 24
        targetSdk 36

        ndk {
            abiFilters 'arm64-v8a'
        }

        externalNativeBuild {
            cmake {
                cppFlags "-O2 -fvisibility=hidden"
            }
        }
    }

    buildTypes {
        release {
            minifyEnabled true
            shrinkResources true
            proguardFiles ...
        }
    }

    externalNativeBuild {
        cmake {
            path 'src/main/cpp/CMakeLists.txt'
            version '3.22.1'
        }
    }
}

dependencies {
    implementation 'com.google.android.material:material:1.12.0'
    implementation 'androidx.appcompat:appcompat:1.7.0'
    implementation 'androidx.recyclerview:recyclerview:1.3.2'
    implementation 'androidx.cardview:cardview:1.0.0'
    implementation 'androidx.coordinatorlayout:coordinatorlayout:1.2.0'
}
```

### CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.22.1)
project("antifrida")

add_library(${CMAKE_PROJECT_NAME} SHARED
    native-lib.cpp
    detector/thread_detector.cpp
    detector/memory_scanner.cpp
    detector/port_scanner.cpp
    detector/hook_detector.cpp
    detector/anti_debug.cpp
    utils/syscall_utils.cpp
)

target_link_libraries(${CMAKE_PROJECT_NAME} android log)

# 16KB page size alignment for Android 15+
if(ANDROID_ABI STREQUAL "arm64-v8a")
    target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,-z,max-page-size=16384")
endif()
```

---

## 代码示例

### Java: 执行检测

```java
// MainActivity.java
private void runDetection() {
    showLoading(true);

    new Thread(() -> {
        List<DetectionResult> results = detectionManager.runAllDetections();

        runOnUiThread(() -> {
            adapter.setData(results);
            updateStatusCard(results);
            showLoading(false);
        });
    }).start();
}
```

### C++: 线程检测

```cpp
// thread_detector.cpp
bool detect_frida_threads() {
    DIR* dir = opendir("/proc/self/task");
    struct dirent* entry;

    while ((entry = readdir(dir)) != NULL) {
        char path[256];
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", entry->d_name);

        char thread_name[256];
        FILE* fp = fopen(path, "r");
        if (fp) {
            fgets(thread_name, sizeof(thread_name), fp);
            fclose(fp);

            // 检查 Frida 关键词
            if (strstr(thread_name, "frida") ||
                strstr(thread_name, "gum-js")) {
                return true; // 检测到 Frida
            }
        }
    }
    closedir(dir);
    return false;
}
```

### JNI: Java 与 Native 桥接

```cpp
// native-lib.cpp
extern "C" JNIEXPORT jboolean JNICALL
Java_anti_rusda_MainActivity_nativeDetectFridaThread(JNIEnv* env, jobject thiz) {
    return detect_frida_threads();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_anti_rusda_MainActivity_nativeDetectFridaPort(JNIEnv* env, jobject thiz) {
    return scan_frida_ports();
}
```

---

## 安全特性

### 1. 反 Hook 设计
- **直接系统调用**: 绕过 libc 函数 hook
- **自定义字符串函数**: 防止 inline hook
- **符号隐藏**: `-fvisibility=hidden`

### 2. 代码保护
- **ProGuard 混淆**: Java 代码混淆
- **Native 符号隐藏**: Native 函数名隐藏
- **16KB 对齐**: Android 15+ 兼容性

### 3. 检测覆盖
- **多层检测**: Java + Native 双引擎
- **行为分析**: 线程/端口/内存/文件多维度
- **环境感知**: Root/模拟器/调试器/多实例

---

## 扩展指南

### 添加新检测项

1. **Java 层**: 在 `DetectionManager.java` 中添加方法
2. **Native 层**: 在 `detector/` 下创建新的检测器
3. **JNI 接口**: 在 `native-lib.cpp` 中导出函数
4. **UI 展示**: 更新 `strings.xml` 添加本地化文本

### 添加新语言

1. 创建 `res/values-[语言代码]/strings.xml`
2. 复制英文文本并翻译
3. 在 `SettingsActivity` 中添加语言选项

---

## 项目统计

| 类型 | 数量 |
|------|------|
| Java 源文件 | 7 个 |
| C++ 源文件 | 7 个 |
| 布局文件 | 3 个 |
| 字符串资源 | 2 种语言 |
| 检测项 | 12 项 |
| 矢量图标 | 13 个 |

---

**版本**: v1.0.0
**作者**: rusda
**许可证**: Open Source
