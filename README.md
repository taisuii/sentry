# Sentry · Android Runtime Security Sentinel

**中文**：面向风控与移动安全研究的多信号本地检测引擎：Java 编排 + Native 对抗，syscall 优先、多通道交叉验证，将结论做成可解释、可量化的运行时画像。  
**English**: A multi-signal on-device detection engine for risk control and mobile security research: Java orchestration meets native adversarial checks—syscall-first I/O, redundant cross-channel validation, and an interpretable, weighted risk score.

---

## Screenshots · 界面预览

| Overview · 概览 | Debug · 调试检测 |
|:---:|:---:|
| ![Overview](img/homepage.png) | ![Debug](img/debugscreen.png) |

| Environment · 环境检测 | More · 更多 |
|:---:|:---:|
| ![Environment](img/envscreen.png) | ![More](img/screenshot.png) |

---

## Detection surface · 检测覆盖面

**中文**：共 **21** 项：调试域 **11**（Frida / 端口与进程 / 内存与 maps / ptrace与调试器 / Xposed·Hook 框架 / SO 代码段完整性 / ArtMethod / Hook 陷阱 / 脏页与内存注入等），环境域 **10**（签名校验、Bootloader·Key Attestation、Magisk/Root、危险应用、可疑路径、模拟器、内核补丁陈旧度、ADB、多开、容器与 cgroup 等）。状态 `NORMAL` / `WARNING` / `DANGER`，核心项加权、辅助项降权，`warnOnly` 仅提示不扣分。  

**English**: **21** checks in two domains—**11** anti-debug / instrumentation (Frida thread & port signals, memory/maps, ptrace & debugger attachment, Xposed/hook framework, in-memory SO integrity, ArtMethod entry, SIGTRAP hook trap, dirty-page / injection heuristics, etc.) and **10** environment & integrity (APK signature gating, Bootloader + Key Attestation RootOfTrust, Magisk/root, “dangerous apps”, suspicious paths, emulator heuristics, patch staleness, multi-channel ADB, multi-instance, container/cgroup). Tri-state outcomes with **weighted scoring** and **`warnOnly`** items that alert without tanking the score.

---

## Technical depth · 技术深度（核心“肌肉”）

### 中文

1. **双引擎与生命周期闸门**  
   敏感逻辑下沉 **Native**（`libantidebug` / `libenvdetect`），Java 侧负责调度与展示。**Release** 下将当前 APK 签名 **SHA-256** 与构建期注入的期望值在 **Native** 比对；不匹配时在应用最早阶段终止，缩小 UI/业务层绕过窗口。

2. **syscall 优先与 I/O 回退**  
   读 `/proc`、套接字探测等路径大量使用直 **syscall**（`open`/`read`/`connect`/…），减少对 **glibc** 常规导出符号的依赖，降低 **Frida / Xposed 对 libc 的一刀切 Hook** 带来的系统性失效。在受限机型上配合 **syscall → libc** 的 **fallback**，兼顾对抗强度与兼容性。

3. **多通道：不把可信度绑在单一 API**  
   - **Maps**：Native 读 `maps` + Java **`Runtime.exec("cat /proc/<pid>/maps")`** 二次扫描，对抗只 patch 一条读路径的绕过。  
   - **ADB**：Native（端口、`/proc/net/tcp`、**adbd** 进程、**sysfs** USB 状态）+ Java **Settings** + **`getprop`/`settings get` exec 兜底**，对抗单一 ContentResolver Hook。  
   - **Bootloader**：**`ro.boot.*`** 等属性 + **Key Attestation** 证书链中的 **RootOfTrust**（`deviceLocked`、`verifiedBootState`、`verifiedBootKey` 等），属性覆盖面广、TEE 侧证据置信度高。  
   - **Xposed/Hook**：Java（类名、堆栈、反射、**ClassLoader** 指纹）与 Native（路径/**fd**、**inline/PLT·GOT**、可疑匿名 **r-x**、**ARM64 LR** 等）组合，避免“只盯 Java 或只盯 maps”的盲区。

4. **Frida / 调试用工具的工程级覆盖面**  
   除 **27042 / 23946** 等端口与 **`/proc/net/tcp` LISTEN** 解析外，覆盖 **frida-server** 随机端口场景（按进程 **comm** 关联其 **`/proc/<pid>/net/tcp`**）、**re.frida** 等进程名扫描，并对 **127.0.0.1** 上疑似监听端口做短时 **D-Bus AUTH** 试探（典型 **REJECT** 响应作为强特征），与线程 **`/proc/self/task/*/comm`** 关键词、**maps** 签名共同构成证据链。

5. **内存与映射：不止字符串匹配**  
   在 **maps** 签名之外，对**匿名可执行映射**做规模与白名单约束，并扫描 **ARM64** 上 **LDR + BR** 一类 **trampoline** 指令序列；对 **LSPosed / Zygiske** 等“隐藏 so 仍留 r-x”场景保留敏感度（可选“高级检测”降低匿名段大小阈值以换取更高检出、更高误报风险）。

6. **SO 代码完整性：面向 SELinux / XOM 的现实解法**  
   放弃易踩 **权限与 Execute-Only Memory** 雷区的“读磁盘 code 段做哈希”路径，转而 **`dl_iterate_phdr` 定位已映射的 `libc.so` 可执行段**，在**进程内已映射内存**上做 **hook 型指令模式**扫描；并辅以**匿名 r-xp** 异常段启发式。**不做 untrusted_app 直读系统分区**的前提下仍可给出高价值信号。

7. **ArtMethod 与 Java 层 Hook**  
   通过 JNI 取得 **`Activity.onCreate` 的 jmethodID**，在 **ART** 语义下读取 **entry point**，与 **`/proc/self/maps` 汇总的合法 code 区间**比对；典型 **Frida Java hook** 会将入口指向 **libart/oat 之外的可执行岛**，用于与纯 maps 文本扫描互补。

8. **Hook Trap：信号路径上的对抗探针**  
   自行安装 **SIGTRAP** handler，经 **syscall `kill(self, SIGTRAP)`** 触发；若信号未被自有 handler **longjmp** 链路消化，可作为“异常 handler/inline hook 链”的佐证之一（与内存、PLT 等静态特征互为补充）。

9. **脏页与注入：Smaps / Pagemap / VMap**  
   读取 **`smaps`** 关注关键映射上 **`Private_Dirty`** 等脏页异常；结合 **`/proc/self/pagemap`** **soft-dirty（bit 55）** 等对 **COW/改写**敏感的信号；并对匿名映射做**特征串**搜索——面向 **Zygisk、注入型框架**等“落地后必有内存痕迹”的场景，而非单靠包名。

10. **环境与完整性 adjacent**  
   Root/Magisk 路径与包名、**APK ZIP** 内 **`assets/xposed_init`**、**modules.list** 等与 Java **`GET_META_DATA`** 列表形成**危险应用**多通道；**容器**侧结合包名/`cmdline` 不一致与 **`/proc/1/cgroup`** 等信号。

11. **评分语义**  
   总分由加权求和构成（满分 **205** 按当前项权重）；**`warnOnly`** 在 **WARNING** 时仍计满分，仅 UI 警示——把“开发机常开 ADB、补丁偏旧、装有 Xposed 模块但不等于正在 hook 本进程”等场景从分数里解耦，减少运营误伤。

### English

1. **Dual-engine gating**  
   Instrumentation-heavy work lives in **native** libraries; Java drives orchestration and UX. On **release** builds, **SHA-256** of the running APK is checked against a **compile-time injected** expected fingerprint **in native code**—fail-fast at process start shrinks the attack window before business/UI layers run.

2. **Syscall-first I/O with pragmatic fallback**  
   `/proc` traversal, local socket probes, and similar hot paths favor **direct syscalls** over libc exports to stay useful when **libc is broadly instrumented**. Where devices tighten behavior, **syscall → libc** **fallback** keeps reads working without giving up the stronger path by default.

3. **Redundant channels instead of single-API faith**  
   **Maps** pairs native parsing with a **`cat /proc/<pid>/maps`** Java exec path. **ADB** chains native port/`tcp`/process/sysfs signals with Java **Settings** reads and **`getprop` / `settings get`** exec backups. **Bootloader** merges **`ro.boot.*`-class properties** with **Key Attestation RootOfTrust** fields (`deviceLocked`, `verifiedBootState`, `verifiedBootKey`, …). **Hook frameworks** combine Java-side class/stack/reflection/**ClassLoader** probes with native path/**fd**, **inline/PLT·GOT**, suspicious **anonymous r-x**, and **ARM64 LR** checks.

4. **Frida / tool-server coverage beyond “one port”**  
   Alongside **27042 / 23946** connects and **`/proc/net/tcp` LISTEN** parsing, the stack handles **Frida 16+**-style randomized ports by correlating **`frida-server`** **comm** with that PID’s **`net/tcp`** view, scans **`re.frida`/`frida-server`**-like tasks, and issues short **D-Bus AUTH** probes on localhost listeners (**REJECT**-shaped replies as a high-signal cue)—combined with **thread name** and **maps** evidence.

5. **Memory analysis above naive substring scans**  
   Beyond **maps** signature passes, anonymous **r-x** regions are gated with size/whitelist rules and **ARM64** **LDR+BR “trampoline”** pattern hunts; an optional **“advanced”** mode tightens anonymous thresholds for higher sensitivity (and higher false-positive pressure).

6. **SO integrity without disk reads that break on modern Android**  
   Rather than hashing on-disk **`/system`/`/apex`** segments that **SELinux** or **XOM** can block or fault on, the engine walks `/proc/self/maps` via **`dl_iterate_phdr`**, scans **in-process** **libc** **RX** ranges for **hook-shaped** instruction patterns, and augments with **anonymous r-xp** heuristics—strong signal **without** requiring direct filesystem reads of system libraries.

7. **ArtMethod entry vs. legitimate code islands**  
   JNI resolves **`Activity.onCreate`**, reads the **ArtMethod entry point**, and tests membership against **executable ranges** distilled from **`/proc/self/maps`**—a complementary angle to textual **maps** matches for **Java-method hooks** that relocate trampolines outside **libart**/OAT.

8. **SIGTRAP hook trap**  
   A dedicated **SIGTRAP** handler plus **syscall `kill(self, SIGTRAP)`** verifies that the process still controls the signal disposition—useful when **foreign handlers** or **hook chains** swallow or reorder trap delivery; meant to **corroborate**, not replace, memory/PLT evidence.

9. **Dirty pages & injection: smaps + pagemap + vmap**  
   **`smaps`** watches **Private_Dirty** on sensitive mappings; **`pagemap`** **soft-dirty (bit 55)** captures **COW/dirtied-page** fingerprints often left behind by **inline rewrites**; **anonymous** regions get targeted **string** scans—aimed at **post-injection** artifacts, not package-name trivia alone.

10. **Environment & adjacent threats**  
   Magisk/root paths and packages; **Xposed module** discovery merges Java **`GET_META_DATA`/launcher queries** with native **ZIP/`assets/xposed_init`** probes and **`modules.list`** reads where accessible; **virtualization** blends package/`cmdline` mismatches and **`/proc/1/cgroup`** hints (`lxc`, `docker`, `kubepods`, …).

11. **Scoring semantics**  
   The dashboard aggregates **weighted** item scores (current design totals **205** points at full credit). **`warnOnly`** flips **WARNING** into a **no-penalty** alert—keeping developer realities (ADB enabled, stale patch level, modules installed but not attacking this app) from dominating the headline percentage.

---

## Further reading · 延伸阅读

技术原理、关键代码摘录与 21 项速查见 **`doc/DETECTION_SPEC.md`**。
