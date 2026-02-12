# Sentry 检测规范文档

本文档详细描述 Sentry 安全检测应用中的各项检测、评分机制、实现方式以及设计目的。

> **维护要求**：本规范应与代码实现保持同步。根据 `.cursor/rules/modify-after-structure.mdc`，重大变更（如新增/删除检测项、修改实现层或逻辑等）完成后，须同步更新本文档及 `.cursor/skills/sentry-project-structure/SKILL.md`。  
> **一致性**：本文档已与当前代码库对齐（检测项 9+9=18、权重、JNI/Native 接口、文件路径）。

---

## 一、检测总览

Sentry 提供 **18 项** 安全检测，分为两类：

| 类别       | 数量 | 管理类                     | 展示位置   |
|------------|------|----------------------------|------------|
| 调试检测   | 9    | `DebugDetectionManager`    | 调试检测 Tab |
| 环境检测   | 9    | `EnvDetectionManager`     | 环境检测 Tab |

### 1.1 检测项与权重一览表

| 序号 | 检测项标题 | 类别 | maxScore | warnOnly | 说明 |
|------|------------|------|----------|----------|------|
| 1 | Frida Threads | 调试 | 10 | — | 检测 Frida 线程名 |
| 2 | Frida Ports | 调试 | 10 | — | 检测 Frida 默认端口 |
| 3 | Memory Signatures | 调试 | 10 | — | 内存映射 Frida/LSPosed 签名（Native syscall 读 maps） |
| 4 | Maps 二次检测 (Java exec) | 调试 | 10 | — | 通过 Runtime.exec 读 /proc/pid/maps 二次扫描，与 Native 双通道 |
| 5 | Named Pipes | 调试 | 10 | — | Unix 域套接字/管道名 |
| 6 | Ptrace / IDA Attach | 调试 | 10 | — | TracerPid 检测 |
| 7 | Debugger Attached | 调试 | 10 | — | Debug.isDebuggerConnected() |
| 8 | Xposed / Hook Framework | 调试 | 10 | — | Xposed/LSPosed + Native Hook |
| 9 | Dirty Page / Memory Injection | 调试 | 10 | — | Smaps Private_Dirty + VMap + Pagemap bit 55 脏页/内存注入特征 |
| 10 | Bootloader | 环境 | **15** | — | 启动验证/锁定状态 + TEE RootOfTrust |
| 11 | Magisk / Root | 环境 | **12** | — | Magisk/root 环境 |
| 12 | Dangerous Apps | 环境 | **5** | **是** | 多渠道检测 Xposed 模块（meta-data、APK assets/xposed_init、modules.list）；仅警告不扣分 |
| 13 | Suspicious Files | 环境 | 10 | — | Frida/Magisk 等可疑路径 |
| 14 | Emulator | 环境 | 10 | — | 模拟器特征 |
| 15 | Kernel Patch | 环境 | 10 | **是** | 安全补丁陈旧度；过期仅警告不扣分 |
| 16 | ADB Debug | 环境 | **5** | **是** | 仅警告不扣分 |
| 17 | Multi-instance | 环境 | **5** | — | 多开/分身环境 |
| 18 | Container / Virtualization | 环境 | **8** | — | 容器/虚拟化 |

---

## 二、调试检测（9 项）

### 2.1 Frida Threads

| 属性     | 说明 |
|----------|------|
| **目的** | 检测 Frida 运行时创建的典型 GLib/线程名，用于发现 Frida 注入 |
| **实现层** | Native（C++，`thread_detector.cpp`） |
| **实现** | 使用 syscall（`my_open`/`my_read`/`my_close`）读取 `/proc/self/task/*/comm`，`my_strcasestr` 匹配关键词：`gmain`、`gdbus`、`pool-spawner`、`frida-agent`、`frida-gadget`、`frida`、`gum-js-loop`、`gthread`、`gpool`、`gjs-context`、`frida-helper` |
| **状态** | 检测到任意匹配 → `DANGER`；未检测 → `NORMAL` |

### 2.2 Frida Ports

| 属性     | 说明 |
|----------|------|
| **目的** | 检测 Frida 默认监听端口、Frida Server 进程及 Frida 相关进程（如 `re.frida.helper`），防止 Frida 远程附加或注入 |
| **实现层** | Native（C++，`port_scanner.cpp`） |
| **实现** | 1) 使用 **syscall**（`my_socket`/`my_connect`）连接本地 `127.0.0.1` 端口 **27042**（仅检测此端口）；2) 读取 **`/proc/net/tcp`**（系统级 TCP 表），仅匹配状态 **0A(LISTEN)** 行中本地端口为 `:699A`（27042，边界匹配）；3) **Frida 16+ 随机端口**：遍历 `/proc/<pid>/comm`，若进程名包含 `frida-server`，则读取该进程的 `/proc/<pid>/net/tcp`，若存在状态 `0A`（LISTEN），判为 Frida Server 监听（覆盖 `-l 0.0.0.0:0` 随机端口场景）；4) **Frida 进程扫描**：遍历 `/proc/<pid>/comm`，若进程名包含 `re.frida`（匹配 `re.frida.helper`、`re.frida.server` 等）或 `frida-server`，判为 Frida 进程存在（Frida 运行时会留下如 `re.frida.helper` 进程） |
| **状态** | 任意经典端口可连接、net/tcp 发现经典端口、frida-server 进程存在 LISTEN 套接字、或发现 Frida 相关进程（如 re.frida.helper）→ `DANGER`；否则 `NORMAL` |
| **设计说明** | 使用 syscall 绕过 libc；移除 5000/8080 以降低误报；通过进程名 + net/tcp 覆盖 Frida 16+ 随机端口；Frida 进程扫描覆盖 gadget 注入时产生的 `re.frida.helper` 等进程 |

### 2.3 Memory Signatures

| 属性     | 说明 |
|----------|------|
| **目的** | 检测进程内存映射中是否存在 Frida/LSPosed 相关库或字符串；**增强**：匿名可执行内存（LSPosed 隐藏 so 时仍保留可执行权限） |
| **实现层** | Native（C++，`memory_scanner.cpp`） |
| **实现** | 1) **签名匹配**：使用 syscall `my_open`/`my_read` 读取 `/proc/self/maps`，逐行匹配 `frida`、`FRIDA`、`gum-js`、`gobject`、`gmain`、`frida-agent`、`frida-gadget`、`frida-server`、`liblspd.so`、`libriru.so`、`libriruloader.so`、`libxposed`、`org.lsposed`、**zygisk_lsposed**、**zygisk**（覆盖 maps 中 `/data/adb/modules/zygisk_lsposed/zygisk/arm64-v8a.so`）等；2) **匿名可执行内存**：解析 maps 行，识别匿名路径（排除 [vdso]/[vvar]/[stack]/[heap]）+ 可执行权限 + 大小 ≥128KB 的映射，最多报告 2 条，用于发现 LSPosed 等隐藏 so 后仍保留的可执行代码 |
| **状态** | 发现任一签名或可疑匿名可执行内存 → `DANGER`；未发现 → `NORMAL` |
| **设计说明** | 通过 syscall 与自实现字符串函数减少 inline hook 风险；匿名可执行内存检测阈值 default 128KB 降低 JIT 误报；**设置 → 高级检测** 开启后阈值降至 4KB，可发现更小匿名可执行区（可能增加误报） |

### 2.4 Maps 二次检测 (Java exec)

| 属性     | 说明 |
|----------|------|
| **目的** | 与 Native 层读 `/proc/self/maps` 形成双通道：通过 **Runtime.exec("cat /proc/\<pid\>/maps")** 获取 maps 内容，逐行检查是否包含可疑模块签名，用于交叉验证或绕过仅 hook 了 syscall 的场景 |
| **实现层** | Java（`DebugDetectionManager.detectMapsViaExec()`） |
| **实现** | `Process.myPid()` 获取当前 PID，执行 `cat /proc/<pid>/maps`，`BufferedReader` 逐行读取；每行与 `MAPS_SUSPICIOUS_SIGNATURES` 做不区分大小写匹配（与 `memory_scanner.cpp` 的 FRIDA_SIGNATURES 一致：frida、gum-js、gobject、gmain、liblspd.so、libriru.so、libxposed、org.lsposed、zygisk 等）；命中则 DANGER，最多记录 16 条详情；exec 失败或异常时 WARNING |
| **状态** | 发现任一行包含可疑签名 → `DANGER`；未发现 → `NORMAL`；无法执行/读取 → `WARNING` |
| **设计说明** | 检测两次 maps：一次 Native syscall，一次 Java exec，降低单一通道被 hook 导致漏检的概率 |

### 2.5 Named Pipes

| 属性     | 说明 |
|----------|------|
| **目的** | 检测 Frida 使用的 Unix 域套接字/管道名 |
| **实现层** | Java |
| **实现** | 读取 `/proc/self/net/unix`，搜索包含 `frida`、`gmain`、`gdbus` 的行 |
| **状态** | 发现 → `DANGER`；未发现 → `NORMAL` |

### 2.6 Ptrace / IDA Attach

| 属性     | 说明 |
|----------|------|
| **目的** | 检测当前进程是否被 ptrace 附加（如 IDA、gdb 附加调试） |
| **实现层** | Java |
| **实现** | 读取 `/proc/self/status`，解析 `TracerPid:` 字段；非 0 表示被附加 |
| **状态** | `TracerPid != 0` → `DANGER`；否则 `NORMAL` |

### 2.7 Debugger Attached

| 属性     | 说明 |
|----------|------|
| **目的** | 检测 Android 调试器是否已连接 |
| **实现层** | Java |
| **实现** | 调用 `Debug.isDebuggerConnected()` |
| **状态** | 已连接 → `DANGER`；否则 `NORMAL` |

### 2.8 Xposed / Hook Framework

| 属性     | 说明 |
|----------|------|
| **目的** | 检测 Xposed/LSPosed/EdXposed 框架及内联/PLT Hook、特征路径与注入 fd |
| **实现层** | Java + Native（`hook_detector.cpp`、`xposed_detector.cpp`、`memory_scanner.cpp`）；入口方法名 `checkLibraryIntegrity(Context)` |
| **实现** | 1) **Java**（检测**当前进程**是否被 hook，非「应用安装」）：① `Class.forName("de.robv.android.xposed.XposedBridge")`；② **堆栈检测**：自造异常，检查堆栈中是否包含 `XposedBridge`/`XposedHelpers`/`org.lsposed`；③ **反射检测**：反射查找 `XposedHelpers`/`XposedBridge` 的 `findAndHookMethod`、`hookAllMethods` 等关键方法；④ **ClassLoader 实例检测**：`VMDebug.getInstancesOfClasses` 遍历 ClassLoader，检查 `InMemoryClassLoader`、`LspModuleClassLoader`、`XposedBridge`、`EdXposed`，尝试加载 `org.lsposed.lspd.core.Main`，检查 parent 链含 Xposed/Lsp（需绕过 Hidden API）。2) **Native**：⑤ **特征路径与 fd**（`xposed_detector.cpp`，syscall）：检测 Xposed 路径、**LSPosed 路径**（`/data/adb/lspd`、`/data/adb/modules/zygisk_lsposed`）、**Riru 路径**、**ro.dalvik.vm.native.bridge** 可疑值、**Zygisk fexecve**（`/proc/self/exe` 为 `/dev/fd/X`）、**LD_PRELOAD/MAGISKTMP** 环境变量、`/proc/self/fd` 中 `linjector`/`lsposed`/`riru`；⑥ **内存映射**（`memory_scanner.cpp`）：`/proc/self/maps` 中匹配 `libxposed`、`XposedBridge`、`XposedHelpers`、`org.lsposed`、`zygisk_lsposed`、`zygisk` 等签名；⑦ 内联 Hook、PLT/GOT、libc 完整性（`hook_detector.cpp`）；⑧ **LR 寄存器检测**（`hook_detector.cpp`，ARM64）：在 `detect_hooks()` 入口读取 LR(x30)，若返回地址不在本模块（libantidebug.so）范围内则判为 trampoline 式 inline hook（Frida/Dobby/xhook 等），使用 syscall 解析 `/proc/self/maps` 获取模块边界。 |
| **状态** | 任意一项命中 → `DANGER`；否则 `NORMAL` |

### 2.9 Dirty Page / Memory Injection（脏页/内存注入）

| 属性     | 说明 |
|----------|------|
| **目的** | 检测可执行段脏页及内存注入特征（Smaps Private_Dirty、Pagemap soft-dirty、VMap 特征），可发现 Zygisk、Frida、LSPosed 等注入，但不限于 Zygisk |
| **实现层** | Native（`env_detector.cpp`，`env_detect_zygisk_injection`，由调试检测 Tab 调用 libenvdetect） |
| **实现** | 1) **Smaps 检测**：读取 `/proc/self/smaps`，解析可执行段（`r-xp`/`r-x`），若 `.so` 或关键系统库（`libart.so`、`libc.so`、`libc++.so`、`libselinux.so`、`libandroid_runtime.so`）映射段中 `Private_Dirty > 0` 则判为可疑脏页/注入（正常代码段不应有 Private_Dirty）；**白名单**：`libstagefright.so`（如 `/system/lib64/libstagefright.so`）等允许有 Private_Dirty，不报；2) **VMap 检测**：扫描 `/proc/self/maps`，对匿名可执行映射读取内存，搜索 Zygisk/Frida 等特征字符串；3) **Pagemap bit 55 (soft-dirty) 检测**：读取 `/proc/self/pagemap`，检查 libc 关键函数所在页的 bit 55 是否置位（inline hook 触发 COW 后该位永久置位）。使用 syscall 绕过 libc。 |
| **状态** | 任意一项命中（且未命中白名单）→ `DANGER`；否则 `NORMAL` |
| **设计说明** | 本质为「脏页检测」，能发现 Zygisk、Frida、LSPosed 等注入，故名称采用「Dirty Page / Memory Injection」以更准确反映实现。Smaps 白名单（`SMAPS_WHITELIST_SO`）用于排除系统/媒体栈正常少量脏页（如 libstagefright）。Native 实现仍在 libenvdetect，由 DebugDetectionManager 加载 envdetect 后调用。 |

---

## 三、环境检测（9 项）

### 3.1 Bootloader

| 属性     | 说明 |
|----------|------|
| **目的** | 检测 Bootloader 锁定状态与启动验证配置，**包含** TEE Key Attestation 的 RootOfTrust（verifiedBootKey、deviceLocked、verifiedBootState、verifiedBootHash） |
| **实现层** | Native（`env_detector.cpp`）+ Java（`KeyAttestationHelper`） |
| **实现** | 1) **Native**：读取 `ro.boot.verifiedbootstate`、`ro.boot.flash.locked`、`ro.boot.veritymode`、`ro.boot.vbmeta.device_state`、`sys.oem_unlock_allowed` 等；`orange`、`vbmeta.device_state=unlocked`、`flash.locked=0`、`veritymode=disabled` 判为 DANGER；`yellow`（自定义密钥）、`oem_unlock_allowed=1` 判为 WARNING；与 `/proc/cmdline` 交叉验证以检测 prop hook。2) **OEM 解锁交叉验证**（Java）：尝试 `Settings.Global.oem_unlocking_enabled` / `oem_unlock_enabled`，与 Native 的 `sys.oem_unlock_allowed` 对比；二者不一致时判为 WARNING。**注意**：`sys.oem_unlock_allowed` 与 Settings 在多数设备上对普通应用**不可读**（系统限制），常显示 0/空；真正可靠的 Bootloader 解锁检测依赖 Key Attestation 的 `deviceLocked` 与 `ro.boot.*` 属性。3) **Key Attestation**：证书链完整性校验、RootOfTrust 解析；`verifiedBootKey` 全零（非模拟器）、`deviceLocked=false`、`verifiedBootState=Unverified(2)` 或 `Failed(3)` 判为 DANGER；SelfSigned(1)、启动 &lt;1 分钟判为 WARNING；API&lt;28 不可检测时返回 NORMAL。 |
| **状态** | Native 或 Key Attestation 任一项 DANGER → `DANGER`；`warranty_bit=1` 或 AVB 版本缺失 → `WARNING`；verifiedBootKey 全零 / deviceLocked=false / Unverified 或 Failed → `DANGER`；SelfSigned → `WARNING`；Verified → `NORMAL`；API&lt;28 或 attestation 不可用 → `WARNING`；RootOfTrust 解析失败 → `NORMAL`（避免误报） |
| **误报控制** | RootOfTrust 结构不被当前解析器识别时视为 NORMAL |
| **权重** | `maxScore = 15` |
| **详情展示** | 系统属性（verifiedbootstate、flash.locked、veritymode 等）+ **OEM Unlock Cross-Verify**（Settings.Global vs Native）+ Key Attestation 的 **Device State**（deviceLocked、verifiedBootState、verifiedBootKey、verifiedBootHash）与 **Security Impact**，与 Hunter 等工具检测一致 |

### 3.2 Magisk / Root

| 属性     | 说明 |
|----------|------|
| **目的** | 检测 Magisk 或其他 Root 环境 |
| **实现层** | Native + Java |
| **实现** | 1) Native：检测 `/data/adb/magisk`、`/data/adb/modules`、Shamiko（zygisk_shamiko）、zygisk_* 模块；2) Java：检查是否安装 `com.topjohnwu.magisk`、`io.github.huskydg.magisk` |
| **状态** | 任意一项存在 → `DANGER` |

### 3.3 Dangerous Apps

| 属性     | 说明 |
|----------|------|
| **目的** | 检测应用列表中是否存在危险应用（如 Xposed 模块），降低 API 被 hook 后的漏检风险 |
| **实现层** | Java + Native（`env_detector.cpp`，`env_verify_xposed_modules`） |
| **实现** | **多渠道**：1) **Java meta-data**：`getInstalledPackages(GET_META_DATA)` + `queryIntentActivities(LAUNCHER)` 双路径获取应用列表，检查 `xposedmodule` / `xposed_module`；2) **风控应用**：检测 MT Manager（`bin.mt.plus`、`com.mi.mi.mtmanager`）、Termux（`com.termux`）；3) **Native APK 校验**：syscall 解析 APK（ZIP）中是否存在 `assets/xposed_init`，绕过 metaData hook；4) **Native modules.list**：尝试读取 `/data/data/de.robv.android.xposed.installer/conf/modules.list`、`/data/adb/lspd/config/modules.list`（Root 时可读）获取已启用模块。Android 11+ 需 `QUERY_ALL_PACKAGES` 权限。 |
| **状态** | 任一渠道发现 Xposed 模块 → `WARNING`；未发现 → `NORMAL` |
| **设计说明** | **warnOnly=true**：仅警告不扣分。检测到危险应用未必代表正在 hook 本应用，仅提示用户设备上存在可 hook 的模块。Native 层使用 syscall 绕过 libc，降低被 hook 风险 |

### 3.4 Suspicious Files

| 属性     | 说明 |
|----------|------|
| **目的** | 检测 Frida Server、Magisk/LSPosed 相关可疑路径 |
| **实现层** | Native（`env_detector.cpp`，`env_detect_suspicious_files`） |
| **实现** | 1) 扫描 `/data/local/tmp` 中文件名包含 `frida-server` 的项；2) 检测路径 `/data/local/tmp/re.frida.server`；3) 检测目录/文件：`/data/adb/magisk`、`/data/adb/modules`、`/data/adb/lspd` 等（具体列表见 `env_detector.cpp` 中 `SUSPICIOUS_ADB_PATHS`） |
| **状态** | 发现任意可疑路径 → `DANGER` |

### 3.5 Emulator

| 属性     | 说明 |
|----------|------|
| **目的** | 检测是否运行在模拟器环境 |
| **实现层** | Native（`env_detector.cpp`，`env_detect_emulator_files`），入参为 `Build.HARDWARE/PRODUCT/DEVICE/BRAND` |
| **实现** | 1) **Build 属性**：上述字段含 `generic`、`unknown`、`google_sdk`、`sdk`、`vbox86p`、`emulator`、`ranchu`、`goldfish` 等（见 `EMULATOR_INDICATORS`）；2) **设备文件**：如 `/dev/socket/qemud`、`/dev/qemu_pipe`、`/system/lib/libc_malloc_debug_qemu.so` 等（见 `EMULATOR_FILES`）；3) **BlueStacks**：`/data/misc/emu/update_check.cfg` |
| **状态** | 发现指标 → `WARNING`（避免对部分真机误报） |

### 3.6 Kernel Patch

| 属性     | 说明 |
|----------|------|
| **目的** | 检测内核安全补丁是否过于陈旧 |
| **实现层** | Java |
| **实现** | 解析 `Build.VERSION.SECURITY_PATCH` 日期，计算距今月数；≥24 月或 ≥12 月均 → `WARNING`（仅提示风险，不代表灰产/恶意设备） |
| **状态** | 补丁过旧仅作警告，不判为危险；**warnOnly=true**，过期不扣分 |

### 3.7 ADB Debug

| 属性     | 说明 |
|----------|------|
| **目的** | 检测开发者选项、USB/WiFi ADB 是否开启，以及 ADB 端口、adbd 进程、sysfs 状态 |
| **实现层** | Java + Native（多通道，降低 API hook 导致漏检） |
| **实现** | **Native（syscall）**：① 端口 syscall connect 检测 5555、5556、5557、5558；② 解析 `/proc/net/tcp` 搜索 ADB 端口十六进制（15B3/15B4/15B5/15B6）；③ 扫描 `/proc/*/comm` 检测 adbd 进程；④ 读取 `/sys/class/android_usb/android0/state` 若为 CONFIGURED/CONNECTED；**Java Settings API**：`development_settings_enabled`、`adb_enabled`、`adb_wifi_enabled`；**Java exec 替代路径**：`getprop init.svc.adbd`、`settings get global adb_enabled`、`adb_wifi_enabled`、`settings get secure development_settings_enabled`，绕过 ContentResolver hook |
| **状态** | 任一通道发现指标 → `WARNING`（仅提示不扣分：`warnOnly=true`，部分设备需开启 ADB 做开发） |

### 3.8 Multi-instance（多开）

| 属性     | 说明 |
|----------|------|
| **目的** | 检测应用是否运行于多开/分身环境 |
| **实现层** | Java |
| **实现** | 包名包含 `:` 或 `dual`；`getFilesDir()` 路径含 `parallel`、`dual`、`clone`、`multi` |
| **状态** | 符合 → `WARNING` |

### 3.9 Container / Virtualization

| 属性     | 说明 |
|----------|------|
| **目的** | 检测 VirtualApp、Parallel Space 等容器/虚拟化环境 |
| **实现层** | Java + Native |
| **实现** | 1) Java：包名 vs `/proc/self/cmdline` 进程名不一致；2) Java：检查 `io.va.exposed`、`com.lody.virtual`、`me.weishu.exp`、`com.parallel.space.lite`、`com.excelliance.dualaid` 是否安装；3) Native：读取 `/proc/1/cgroup` 检测 `lxc`、`docker`、`kubepods` |
| **状态** | 任意一项命中 → `DANGER` |

---

## 四、评分机制

### 4.1 状态与得分

每项检测有三种状态：

| 状态常量 | 数值 | 含义   |  earnedScore |
|----------|------|--------|--------------|
| `STATUS_NORMAL`  | 0 | 正常/安全 | `maxScore`（满分） |
| `STATUS_WARNING` | 1 | 警告     | `maxScore / 2`（若 `warnOnly=true` 则为满分，只提示不扣分） |
| `STATUS_DANGER`  | 2 | 危险     | `0` |

### 4.2 满分与权重

- 默认 `DEFAULT_MAX_SCORE = 10`（见 `DetectionResult.DEFAULT_MAX_SCORE`）
- **核心项加权**（提高对总分的影响）：

| 检测项 | maxScore | 说明 |
|--------|----------|------|
| Bootloader | 15 | 启动验证 + TEE RootOfTrust，与 Hunter 等一致 |
| Magisk / Root | 12 | Root 环境核心指标 |

- **辅助项降权**（避免过度影响总分）：

| 检测项 | maxScore | 说明 |
|--------|----------|------|
| ADB Debug | 5 | 且 `warnOnly=true`，只提示不扣分 |
| Multi-instance | 5 | 多开/分身，非必为恶意 |
| Container / Virtualization | 8 | 容器/虚拟化 |

- 其余 12 项均为默认 10 分

### 4.3 总分计算

```
总分 = Σ earnedScore
满分 = Σ maxScore
安全百分比 = (总分 / 满分) × 100%
```

- 调试检测 7 项 + 环境检测 10 项，共 17 项
- 总分在概览页以百分比形式展示

### 4.4 Native 返回格式

Native 检测统一返回 `String[]`：
- `[0]`：状态数字字符串（`"0"`=NORMAL / `"1"`=WARNING / `"2"`=DANGER）
- `[1]`：摘要 summary（展示在列表主行）
- `[2..n]`：详情 details（展开时展示；若无详情则通常填一条说明如 "No issues detected"）

示例（无异常）：`["0", "No Magisk detected", "No issues detected"]`  
示例（有异常）：`["2", "Magisk or root indicator(s) found", "Suspicious path: /data/adb/magisk"]`

---

## 五、设计与实现原则

### 5.1 Native 优先

- 文件、端口、内存、进程等敏感检测优先放在 **Native 层**
- 降低被逆向、篡改和 hook 的风险
- 调试检测：`DebugDetectionManager` + `native-lib.cpp` + `port_scanner` / `memory_scanner`
- 环境检测：`EnvDetectionManager` + `native-lib-env.cpp` + `env_detector.cpp`

### 5.2 Syscall 优先

- 敏感 I/O、网络、文件访问优先使用 **syscall**，绕过 libc
- 使用 `syscall_utils.cpp` 提供的：`my_open`、`my_read`、`my_close`、`my_access`、`my_socket`、`my_connect`、`my_strstr`、`my_strcmp` 等
- 减少 Frida/Xposed 对 libc 的 hook 影响

### 5.3 误报控制

- 单指标不足以断定异常时，结合多项证据（如模拟器需硬件属性 + 文件 + 端口）
- 不确定时使用 `STATUS_WARNING` 而非 `STATUS_DANGER`
- 特定环境做降级：如 eng/userdebug 构建可将部分检测的 DANGER 降为 WARNING

### 5.4 核心 vs 辅助

- 核心安全项（Frida、Root、ptrace、Key Attestation and Boot 等）可提高 maxScore
- 辅助项（多开、ADB 等）可降低 maxScore，避免过度影响总分

### 5.5 warnOnly（只警告不扣分）

- `DetectionResult` 支持 `warnOnly` 参数。当 `warnOnly=true` 且状态为 `WARNING` 时，`getEarnedScore()` 仍返回满分（与 NORMAL 一致），仅 UI 显示警告。
- 用途：如 **ADB Debug**，部分设备需开启 ADB 做开发，判为危险会误伤，故仅提示、不参与扣分；**Kernel Patch** 安全补丁过期（如约 2 个月）仅提示风险，不代表灰产/恶意设备，故也设为 warnOnly，不扣分；**Dangerous Apps** 应用列表中检测到危险应用（如 Xposed 模块）时仅提示，不扣分（安装模块未必代表正在 hook 本应用）。

---

## 六、检测流程图

```
App 启动
    ↓
DetectionManager 初始化
    ↓
并行执行 {
    DebugDetectionManager.runAllDetections()   ← 8 项
    EnvDetectionManager.runAllDetections()     ← 10 项
}
    ↓
收集 DetectionResult 列表
    ↓
总分 = Σ(earnedScore) / Σ(maxScore)
    ↓
UI 展示（OverviewFragment）
    - 总分百分比
    - 分类详情（调试检测 Tab / 环境检测 Tab）
```

---

## 七、检测项与 UI 展示

- **状态与颜色**：`STATUS_NORMAL`(0) 绿、`STATUS_WARNING`(1) 橙、`STATUS_DANGER`(2) 红
- **概览页**：显示总分百分比 `Σ(earnedScore) / Σ(maxScore) × 100%`，以及设备信息、设备指纹
- **调试/环境 Tab**：每项显示标题、摘要、详情（可展开），列表由 `DetectionAdapter` 渲染

---

## 八、JNI 与 Native 接口速查

调试检测（`libantidebug.so`）由 `native-lib.cpp` 桥接，环境检测（`libenvdetect.so`）由 `native-lib-env.cpp` 桥接。

### 8.1 调试检测 JNI（DebugDetectionManager → native-lib.cpp）

| Java 方法 / 检测项 | JNI 函数名 | C++ 实现 |
|--------------------|------------|----------|
| detectFridaThreads | `nativeDetectFridaThreads` | `thread_detector` |
| detectFridaPorts | `nativeGetFridaPortScanResult` | `port_scanner` |
| detectMemorySignatures | `nativeGetMemorySignatureResult` | `memory_scanner` |
| detectMapsViaExec      | —（Java exec）                   | 读 `/proc/pid/maps` 二次检测 |
| detectNamedPipes | — | Java 读 `/proc/self/net/unix` |
| detectPtraceStatus | — | Java 读 `/proc/self/status` (TracerPid) |
| detectDebuggerAttached | — | Java `Debug.isDebuggerConnected()` |
| checkLibraryIntegrity (Xposed) | `nativeDetectHook`、`nativeDetectXposedPaths` | `hook_detector`、`xposed_detector`、`memory_scanner` |
| detectZygiskInjection（Dirty Page / Memory Injection） | `nativeDetectZygiskInjection`（libenvdetect） | `native-lib-env.cpp` → `env_detect_zygisk_injection`（Smaps + VMap + Pagemap bit 55） |

### 8.2 环境检测 JNI（EnvDetectionManager → native-lib-env.cpp）

| Java 方法 / 检测项 | JNI 函数名 | env_detector 函数 |
|--------------------|------------|--------------------|
| detectBootloader | `nativeDetectBootloader` + `KeyAttestationHelper.runAttestationSync()` | `env_detect_bootloader` 与 Java Key Attestation |
| detectRoot | `nativeDetectMagisk` | `env_detect_magisk` |
| detectXposedModules（Dangerous Apps） | `nativeVerifyXposedModules` | Java 双路径获取应用列表 + Native 校验 APK（assets/xposed_init）、modules.list |
| detectSuspiciousFiles | `nativeDetectSuspiciousFiles` | `env_detect_suspicious_files` |
| detectEmulator | `nativeDetectEmulator` | `env_detect_emulator_files` |
| detectAdbEnhanced | `nativeDetectAdb()` | `env_detect_adb`（端口/net/tcp/adbd/sysfs）；Java Settings API + exec 替代路径（getprop/settings） |
| checkProcessStatus (Multi-instance) | — | Java 包名/FilesDir |
| detectContainer | `nativeCheckCgroup` | `env_detect_cgroup` |

其他：`DeviceFingerprintCollector.nativeGetProcVersion` → `env_read_proc_version()`（用于设备指纹，非检测列表项）。

---

## 九、绕过难度评估

| 检测项 | 绕过难度 | 原因 |
|--------|---------|------|
| Bootloader (Key Attestation) | ⭐⭐⭐⭐⭐ | TEE/KeyStore 签发，RootOfTrust 不可伪造 |
| Frida Ports + Processes (Native) | ⭐⭐⭐⭐ | Syscall 实现，难 Hook；进程扫描覆盖 re.frida.helper |
| Memory Signatures | ⭐⭐⭐⭐ | Syscall + 自实现字符串函数 |
| Frida Threads (Native) | ⭐⭐⭐⭐ | Syscall，难 Hook |
| Magisk/Root (Native) | ⭐⭐⭐⭐ | Syscall 文件检测 |
| Xposed (Java+Native) | ⭐⭐⭐⭐ | 反射 + Native 双检测 + LR 寄存器检测（ARM64） |
| Container (Native cgroup) | ⭐⭐⭐ | 需伪造 cgroup 环境 |
| Debugger Attached | ⭐⭐ | 单 API 调用，易被 Hook |
| Ptrace | ⭐⭐ | 读取 /proc，可被 Hook |
| ADB Debug | ⭐⭐⭐⭐ | Native syscall 多通道 + exec 替代路径，需同时 hook 多层才能绕过 |

---

## 十、检测目的汇总

| 目的             | 对应检测项 |
|------------------|------------|
| 防 Frida 注入    | Frida Threads、Frida Ports、Memory Signatures、Maps 二次检测 (Java exec)、Named Pipes、Suspicious Files、Dirty Page / Memory Injection（脏页 + Pagemap soft-dirty） |
| 防调试器附加     | Ptrace、Debugger Attached |
| 防 Root/Hook     | Magisk/Root、Dirty Page / Memory Injection、Xposed（含 LSPosed 路径/env）、Dangerous Apps、Bootloader（含 Key Attestation） |
| 设备完整性       | Bootloader（含 Key Attestation）、Kernel Patch |
| 防模拟器/容器    | Emulator、Container/Virtualization |
| 开发/运维风险    | ADB Debug、Multi-instance |

---

## 十一、相关文件速查

| 用途         | 路径 |
|--------------|------|
| 调试检测入口 | `app/src/main/java/anti/rusda/detector/DebugDetectionManager.java` |
| 环境检测入口 | `app/src/main/java/anti/rusda/detector/EnvDetectionManager.java` |
| 统一入口（委托 Debug+Env） | `app/src/main/java/anti/rusda/detector/DetectionManager.java` |
| 结果模型     | `app/src/main/java/anti/rusda/detector/DetectionResult.java` |
| Key Attestation（供 Bootloader 调用） | `app/src/main/java/anti/rusda/detector/KeyAttestationHelper.java` |
| 设备指纹采集（概览/非检测项） | `app/src/main/java/anti/rusda/detector/DeviceFingerprintCollector.java` |
| JNI 调试库桥接 | `app/src/main/cpp/native-lib.cpp` |
| JNI 环境库桥接 | `app/src/main/cpp/native-lib-env.cpp` |
| 线程检测     | `app/src/main/cpp/detector/thread_detector.cpp` |
| 端口扫描     | `app/src/main/cpp/detector/port_scanner.cpp` |
| 内存扫描     | `app/src/main/cpp/detector/memory_scanner.cpp` |
| Hook 检测（内联/PLT/GOT/LR 寄存器） | `app/src/main/cpp/detector/hook_detector.cpp` |
| Xposed 路径/fd | `app/src/main/cpp/detector/xposed_detector.cpp` |
| 调试/进程状态（Legacy，MainActivity JNI） | `app/src/main/cpp/detector/anti_debug.cpp`（TracerPid、debug_flag、LD_PRELOAD；主 17 项流程中 Ptrace/Debugger 由 Java 实现） |
| 环境检测 C++（Magisk/Bootloader/Zygisk/模拟器等） | `app/src/main/cpp/detector/env_detector.cpp` |
| Syscall 工具 | `app/src/main/cpp/utils/syscall_utils.cpp` |
| Native 构建（libantidebug + libenvdetect） | `app/src/main/cpp/CMakeLists.txt` |
| 开发规范     | `.cursor/rules/detection-development.mdc` |
| 项目结构速查 | `.cursor/skills/sentry-project-structure/SKILL.md` |

---

## 十二、关键实现与代码速查（供 AI Agent 理解实现）

本节给出**关键代码片段**，便于 AI Agent 或开发者快速理解「我们是怎么实现检测的」。

### 12.1 结果模型与得分计算

**文件**：`app/src/main/java/anti/rusda/detector/DetectionResult.java`

- 状态常量：`STATUS_NORMAL=0`、`STATUS_WARNING=1`、`STATUS_DANGER=2`
- 得分逻辑：NORMAL 得满分，WARNING 得一半（若 `warnOnly=true` 则仍得满分），DANGER 得 0

```java
/** 根据状态得到该项得分：NORMAL=满分，WARNING=一半（warnOnly 时为满分），DANGER=0 */
public int getEarnedScore() {
    switch (status) {
        case STATUS_NORMAL:
            return maxScore;
        case STATUS_WARNING:
            return warnOnly ? maxScore : (maxScore / 2);
        case STATUS_DANGER:
        default:
            return 0;
    }
}
```

### 12.2 调试检测入口与 Native 结果解析

**文件**：`app/src/main/java/anti/rusda/detector/DebugDetectionManager.java`

- 一次执行 7 项检测；敏感项通过 JNI 调用 Native（syscall），避免 Java 层被 Hook。

```java
public List<DetectionResult> runAllDetections(Context context) {
    ensureNativeLoaded();
    List<DetectionResult> results = new ArrayList<>();
    results.add(detectFridaThreads());      // Native
    results.add(detectFridaPorts());        // Native
    results.add(detectMemorySignatures());  // Native
    results.add(detectNamedPipes());        // Java 读 /proc/self/net/unix
    results.add(detectPtraceStatus());     // Java 读 /proc/self/status (TracerPid)
    results.add(detectDebuggerAttached());  // Java Debug.isDebuggerConnected()
    results.add(checkLibraryIntegrity(context)); // Java + Native (Xposed/Hook)
    return results;
}

/** Native 返回 String[]：[0]=状态 "0"|"1"|"2"，[1]=摘要，[2..n]=详情 */
private DetectionResult detectFridaThreads() {
    String[] raw = nativeDetectFridaThreads();
    if (raw == null || raw.length < 2) {
        return new DetectionResult("Frida Threads", "Scan failed", DetectionResult.STATUS_WARNING);
    }
    int status = Integer.parseInt(raw[0]);
    String summary = raw[1];
    List<String> details = raw.length > 2 ? Arrays.asList(Arrays.copyOfRange(raw, 2, raw.length)) : Collections.emptyList();
    DetectionResult result = new DetectionResult("Frida Threads", summary, status);
    result.setDetails(details);
    return result;
}
```

### 12.3 Native 层：Frida 线程检测（syscall + 关键词）

**文件**：`app/src/main/cpp/detector/thread_detector.cpp`

- 使用 **syscall**（`my_open`/`my_read`/`my_close`）读 `/proc/self/task/*/comm`，避免 libc 被 Hook。
- 用自实现 `my_strcasestr` 匹配 Frida 相关线程名。

```cpp
static const char *FRIDA_THREAD_KEYWORDS[] = {
    "gmain", "gdbus", "pool-spawner", "frida-agent", "frida-gadget", "frida",
    "gum-js-loop", "gthread", "gpool", "gjs-context", "frida-helper", nullptr
};

int get_frida_thread_details(char (*details)[256], int max_details) {
    DIR *dir = opendir("/proc/self/task");
    // ...
    snprintf(path, sizeof(path), "/proc/self/task/%s/comm", entry->d_name);
    int fd = my_open(path, 0, 0);   /* syscall，绕过 libc */
    ssize_t bytes = my_read(fd, buffer, sizeof(buffer) - 1);
    my_close(fd);
    // ...
    for (int i = 0; FRIDA_THREAD_KEYWORDS[i] != nullptr; i++) {
        if (my_strcasestr(buffer, FRIDA_THREAD_KEYWORDS[i]) != nullptr) {
            // 命中 → 记录 details，计数 n++
        }
    }
    return n;  // n>0 → JNI 侧判为 DANGER(2)
}
```

### 12.4 内存映射 maps 扫描（双通道）

**Native（主通道）**：`app/src/main/cpp/detector/memory_scanner.cpp`

- 使用 **syscall** `my_open`/`my_read` 读 `/proc/self/maps`，逐行用 `my_strcasestr` 匹配签名。
- **增强**：匿名可执行内存（`check_anon_exec_memory`）：解析 maps 行，识别匿名路径（排除 [vdso]/[vvar]/[stack]/[heap]）+ 可执行权限 + 大小 ≥128KB，最多报告 2 条，用于发现 LSPosed 等隐藏 so 后仍保留的可执行代码。

```cpp
// 1) 签名匹配
for (int j = 0; FRIDA_SIGNATURES[j] != nullptr; j++) {
    if (my_strcasestr(line, FRIDA_SIGNATURES[j]) != nullptr) { ... }
}
// 2) 匿名可执行内存（LSPosed 隐藏 so 时仍保留可执行权限）
check_anon_exec_memory(line, s_findings, MAX_MEMORY_FINDINGS, &s_finding_count, &anon_exec_count);
```

**Java（二次检测）**：`app/src/main/java/anti/rusda/detector/DebugDetectionManager.java` — `detectMapsViaExec()`

- 通过 `Runtime.getRuntime().exec("cat /proc/" + Process.myPid() + "/maps")` 读取 maps，`BufferedReader` 逐行与 `MAPS_SUSPICIOUS_SIGNATURES` 做不区分大小写匹配，与 Native 签名列表一致，形成双通道检测。

### 12.5 Native 层：Frida 端口、frida-server 进程与 Frida 进程扫描

**文件**：`app/src/main/cpp/detector/port_scanner.cpp`

- 仅检测端口 **27042**：`my_socket`/`my_connect` 连接 127.0.0.1:27042；并读 **`/proc/net/tcp`**，逐行仅匹配状态 **0A(LISTEN)** 且本地端口为 `:699A `（边界匹配）。
- Frida 16+ 随机端口：遍历 `/proc/<pid>/comm` 找进程名含 `frida-server`，再读该进程 `/proc/<pid>/net/tcp`，若存在 ` 0A `（LISTEN）则判为 Frida Server 监听。
- **Frida 进程扫描**：`detect_frida_processes()` 遍历 `/proc/<pid>/comm`，若进程名包含 `re.frida`（匹配 `re.frida.helper`、`re.frida.server` 等）或 `frida-server`，记录详情（若 frida-server 已由 LISTEN 检测报告则不再重复）。

```cpp
// 1) connect 检测 27042
// 2) 读 /proc/net/tcp，仅 LISTEN(0A) 行且本地端口 :699A 边界匹配
// 3) detect_frida_server_listening() → frida-server 进程 + LISTEN
// 4) detect_frida_processes() → re.frida.helper、re.frida.server 等进程
bool detect_frida_ports(void) {
    ...
    detect_frida_processes();  // 扫描 /proc/*/comm 检测 Frida 进程
    return found;
}
```

### 12.6 Native 层：环境检测（Magisk、Zygisk/Frida、可疑文件、Cgroup）

**文件**：`app/src/main/cpp/detector/env_detector.cpp`

- **Zygisk/Frida 注入**：① Smaps：`my_open`/`my_read` 读 `/proc/self/smaps`，r-xp 段中 `Private_Dirty > 0` 且为关键库（libart、libc、libselinux、libandroid_runtime）→ 可疑；② VMap：匿名可执行映射搜 `zygisk` 等特征；③ **Pagemap**：`my_open`/`my_lseek`/`my_read` 读 `/proc/self/pagemap`，检查 libc 中 `fork`/`vfork`/`signal` 所在页的 bit 55（soft-dirty），置位表示 COW 曾发生（Frida 指纹）。
- **Magisk**：`my_access`/`file_exists` 检测路径存在性，避免直接用 libc open。

```cpp
static const char *MAGISK_PATHS[] = { "/data/adb/magisk", "/data/adb/modules", nullptr };
static const char *MAGISK_HIDE_MODULE = "/data/adb/modules/zygisk_shamiko";

int env_detect_magisk(char (*details)[256], int max_details) {
    for (const char **p = MAGISK_PATHS; *p && n < max_details; p++) {
        if (file_exists(*p) || is_dir(*p)) {
            snprintf(details[n], 256, "Magisk path: %s", *p); n++;
        }
    }
    if (file_exists(MAGISK_HIDE_MODULE)) { ... }
    // 扫描 /data/adb/modules 下 zygisk_* 目录
    return n;
}
```

- **可疑文件**：扫描 `/data/local/tmp` 下含 `frida-server` 的文件名，以及固定路径 `/data/adb/magisk`、`/data/adb/lspd` 等（见 `SUSPICIOUS_ADB_PATHS`）。
- **容器/虚拟化**：`my_open`/`my_read` 读 `/proc/1/cgroup`，用 `my_strstr` 匹配 `lxc`、`docker`、`kubepods`。
- **ADB 检测**（`env_detect_adb`）：① syscall connect 检测端口 5555–5558；② 解析 `/proc/net/tcp` 搜索 15B3/15B4/15B5/15B6；③ 扫描 `/proc/*/comm` 检测 adbd 进程；④ 读取 `/sys/class/android_usb/android0/state` 若为 CONFIGURED/CONNECTED。

### 12.7 Native 层：Bootloader 状态（系统属性）

**文件**：`app/src/main/cpp/detector/env_detector.cpp`

- 读 `ro.boot.verifiedbootstate`、`ro.boot.flash.locked`、`ro.boot.veritymode` 等；`orange`、`flash.locked=0`、`veritymode=disabled` 判为 DANGER；`warranty_bit=1` 或 AVB 版本缺失仅 WARNING。

```cpp
read_prop("ro.boot.verifiedbootstate", state, sizeof(state));
read_prop("ro.boot.flash.locked", flash_locked, sizeof(flash_locked));
if (my_strstr(state, "orange")) { *out_status = 2; return n; }
if (flash_locked[0] == '0' && flash_locked[1] == '\0') { *out_status = 2; return n; }
if (my_strstr(verity_mode, "disabled")) { *out_status = 2; return n; }
```

### 12.8 JNI 桥接：统一返回格式 String[] { status, summary, detail... }

**文件**：`app/src/main/cpp/native-lib-env.cpp`

- 环境检测 Native 统一通过 `buildResult` 构造 `String[]`：[0]=状态字符串 "0"|"1"|"2"，[1]=摘要，[2..n]=详情。

```cpp
static jobjectArray buildResult(JNIEnv *env, int status, const char *summary,
                                char (*details)[256], int detail_count) {
    jobjectArray arr = env->NewObjectArray(2 + (detail_count > 0 ? detail_count : 1), stringClass, nullptr);
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(statusStr));   // "0"|"1"|"2"
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(summary));
    if (detail_count <= 0)
        env->SetObjectArrayElement(arr, 2, env->NewStringUTF("No issues detected"));
    else
        for (int i = 0; i < detail_count; i++)
            env->SetObjectArrayElement(arr, 2 + i, env->NewStringUTF(details[i]));
    return arr;
}

JNIEXPORT jobjectArray JNICALL Java_..._nativeDetectMagisk(...) {
    char details[MAX_DETAILS][256];
    int n = env_detect_magisk(details, MAX_DETAILS);
    int status = n > 0 ? 2 : 0;  // 2 = DANGER
    return buildResult(env, status, n > 0 ? "Magisk or root indicator(s) found" : "No Magisk detected", details, n);
}
```

### 12.9 Java 层：Bootloader（含 Key Attestation TEE RootOfTrust）

**文件**：`app/src/main/java/anti/rusda/detector/EnvDetectionManager.java` 的 `detectBootloader()`、`KeyAttestationHelper.java`

- Bootloader 检测合并 Native 系统属性 + **OEM 解锁交叉验证** + Key Attestation。`detectBootloader()` 调用 `nativeDetectBootloader()`、进行 OEM 交叉验证（`Settings.Global.oem_unlock_enabled` 与 Native `sys.oem_unlock_allowed` 对比，不一致则 WARNING）、再调用 `KeyAttestationHelper.runAttestationSync()`，取最严重状态合并展示。
- Key Attestation：API 28+ 在 AndroidKeyStore 中生成带 `setAttestationChallenge` 的密钥，取证书链，解析扩展 OID `1.3.6.1.4.1.11129.2.1.17` 中的 ROOT_OF_TRUST。
- 判危：`verifiedBootKey` 全零、`deviceLocked=false`、`verifiedBootState=Unverified(2)` 或 `Failed(3)`；SelfSigned(1) 为 WARNING。解析失败或格式不识别时返回 NORMAL 避免误报。

```java
// KeyAttestationHelper.runAttestationSync()
    KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(ATTESTATION_KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setAttestationChallenge(challenge)
        .build();
    kpg.initialize(spec);
    kpg.generateKeyPair();
    Certificate[] chain = ks.getCertificateChain(ATTESTATION_KEY_ALIAS);
    byte[] extValue = leaf.getExtensionValue(ATTESTATION_EXTENSION_OID);  // "1.3.6.1.4.1.11129.2.1.17"
    RootOfTrust rot = parseRootOfTrust(extValue);
    if (rot == null)
        return new String[]{ String.valueOf(STATUS_NORMAL), "Key attestation: format not recognized (passed)", ... };
    if (rot.verifiedBootKeyAllZeros || !rot.deviceLocked || rot.verifiedBootState == BOOT_UNVERIFIED || rot.verifiedBootState == BOOT_FAILED)
        status = STATUS_DANGER;
    if (rot.verifiedBootState == BOOT_SELF_SIGNED && status != STATUS_DANGER)
        status = STATUS_WARNING;
    return new String[]{ String.valueOf(status), summary, ... };
}
```

### 12.10 环境检测入口与 warnOnly（ADB Debug）

**文件**：`app/src/main/java/anti/rusda/detector/EnvDetectionManager.java`

- `runAllDetections()` 依次调用 10 项环境检测；Native 结果用 `fromNativeResult` 转成 `DetectionResult`。
- **ADB Debug** 检测（多通道抗 hook）：① **Native** `nativeDetectAdb()`：syscall 端口 5555–5558、`/proc/net/tcp`、adbd 进程、sysfs USB 状态；② **Java Settings API**：`development_settings_enabled`、`adb_enabled`、`adb_wifi_enabled`；③ **Java exec**：`getprop init.svc.adbd`、`settings get global adb_enabled` 等，绕过 ContentResolver hook。任一项通道发现 → WARNING。
- 使用 `warnOnly=true`，WARNING 时仍得满分，仅 UI 提示。

```java
return new DetectionResult("ADB Debug", summary, status, 5, details, true);  // warnOnly=true
```

### 12.11 Syscall 工具（绕过 libc）

**文件**：`app/src/main/cpp/utils/syscall_utils.h` / `syscall_utils.cpp`

- 提供：`my_open`、`my_read`、`my_close`、`my_lseek`、`my_access`、`my_socket`、`my_connect`、`my_strstr`、`my_strcasestr`、`my_strcmp` 等，内部使用架构对应 syscall 号（如 `__NR_openat`、`__NR_read`、`__NR_lseek`），避免经过 libc 从而降低被 Frida/Xposed Hook 的概率。
