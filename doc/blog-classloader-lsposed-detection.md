# 用 ClassLoader 计数对抗 LSPosed 隐藏：从看雪思路到 Android 16 落地与真机验证

> 配套实现：[Sentry](https://github.com/taisuii/sentry) 的 D7 检测通道（`class_linker_scan.cpp`）。本文所有日志与截图均取自 Pixel 6 Pro / Android 16（API 36），LSPosed 模块真机注入。

LSPosed 配合 Shamiko 之后，绝大多数传统反 Hook 手段都失效了。扫 `/proc/self/maps` 找异常 SO、`dlopen`/`dlsym` 探框架导出、Java 层抛异常回溯堆栈找 `XposedBridge`——这些都建立在"框架会在某个可观测面留下痕迹"的假设上，而 Shamiko 的全部工作就是抹掉这些痕迹：隐藏文件、隐藏 maps 条目、隐藏包名。攻击者甚至能 Hook `open`/`read` 乃至系统调用，给检测 SDK 喂一份完美的假数据。

看雪 [thread-289567](https://bbs.kanxue.com/thread-289567.htm) 提出了一条跳出 API 维度的思路：不去问系统"装没装框架"，而是直接数虚拟机里**存活的 ClassLoader 数量**。这条路的价值在于它命中了 ART 的一个结构性死局——但原文作者只在 Android 13/14 上验证，并坦言"我的 SDK 目前不敢上线"。本文做三件事：讲清这条死局的原理，把它在 Android 16 上真正跑通（原文实现到了 15/16 会直接失效，原因后面会拆），然后用真机 LSPosed 正负样本对照,证明它能在所有 Java 层检测被绕过时单独把注入抓出来。

---

## 一、死局：ClassLinker 的 `class_loaders_` 链表

ART 的 `Runtime` 持有一个 `ClassLinker`，后者内部维护一条 `std::list`——`class_loaders_`，登记当前进程里所有**存活**的 ClassLoader。这条链表是 GC 可达性的一部分：ClassLoader 在链上，它加载的类和代码就被视为可达，不会被回收。

LSPosed 要把模块代码注入目标进程，就必须为模块创建 `ClassLoader`（实践中是 `InMemoryDexClassLoader`，直接从内存里的 dex 字节加载，连文件都不落地）。于是它陷入一个无法两全的局面：

- **要存活**：模块 ClassLoader 必须挂在 `class_loaders_` 上，否则 GC 判定它不可达，下一轮回收就把模块代码卸了，Hook 当场失效甚至崩溃。
- **要隐藏**：它得从一切可观测面消失。

这两件事在 `class_loaders_` 这条链上是矛盾的。Shamiko 能藏文件、藏 maps、藏包名，因为那些都是"查询接口"，Hook 掉返回值即可；但 `class_loaders_` 是 ART 自己跑 GC 时要遍历的 C++ 堆内存结构，不是给外部查询用的 API。要让自己从链上消失又不被 GC 回收，等于要求 ART 一边认为它可达、一边遍历不到它——做不到。所以**模块 ClassLoader 只能赖在链表里**。只要它在，数一下链表长度就能发现异常。

干净的简单 App 进程通常只有 2-3 个 ClassLoader（BootClassLoader + App 的 PathClassLoader，可能再加一个 WebView）。被 LSPosed 注入后，框架自身、每个启用的模块各自带来额外的 ClassLoader，数量显著抬高。

---

## 二、实现：无符号、纯内存指针运算定位链表

检测的前提是不能依赖任何会被 Hook 的东西——不调 `GetClassLinker`、不 `dlsym`、不碰私有符号（也顺带规避了 Android 7+ 的 linker namespace 隔离）。整条路径只有 C++ 内存指针运算：

1. `JNIEnv->GetJavaVM()` 拿到 `JavaVMExt*`，这是 JNI 标准接口，全版本稳定；
2. 从 `JavaVM` 指针附近探测出 `Runtime*`；
3. 在 `Runtime` 对象内扫描成员指针，找 `ClassLinker*`；
4. 在 `ClassLinker` 内找到 `class_loaders_` 这条 `std::list` 的头，遍历计数。

不同 ROM、不同 ART 版本的结构体布局不一样，硬编码偏移必然碎。所以用运行时特征扫描，三个特征同时成立才锁定：

- **特征 A — VTable 落在 libart**：`ClassLinker` 是有虚函数的 C++ 对象，首 8 字节是虚表指针，该地址必然落在 `/proc/self/maps` 里 `libart.so` 的映射区间内。
- **特征 B — 双向闭环**：`std::list` 底层是双向循环链表，头节点满足 `head->next->prev == head && head->prev->next == head`。
- **特征 C — 节点数合理**：链表至少 2 个节点（Boot + App），且不会是几百个。

三特征叠加，把"恰好长得像链表头的随机内存"的误命中概率压到可以忽略。锁定后缓存三个偏移（`vm→runtime`、`runtime→classlinker`、`classlinker→list`），后续直接走快速路径。

实测扫描日志（Android 16，可以看到特征校验起作用——第一个候选 Runtime 指针在 libart 里找不到合法 vtable 对象，被正确跳过，第二个才命中）：

```
[CLscan] libart range 0x7c10304000-0x7c10f08000
[CLscan] no match in Runtime[0..0xe00]: libart-vtable candidates=0, closed-lists=0
[CLscan] LOCKED cl_off=0x258 list_off=0x60 count=3
[CLscan] located: vm_runtime_off=0x8 cl=0x258 list=0x60 count=3
```

`vm_runtime_off=0x8` 说明在这台机器上 `Runtime*` 就在 `JavaVM + 0x8`；`ClassLinker` 在 `Runtime + 0x258`，`class_loaders_` 在 `ClassLinker + 0x60`。这三个值都是扫出来的，不是写死的。

---

## 三、Android 16 上的两个致命坑（原文实现失效的真正原因）

把原文思路照搬到 Android 16 会直接拿不到结果。调试下来是两个独立的问题，原文作者在 13/14 上都没触发。

### 坑一：指针标签（Pointer Tagging / TBI）污染所有比较

arm64 的 Top-Byte-Ignore 加上 Android 的堆指针标签，会让 `GetJavaVM` 返回的指针顶字节带上 tag。实测这台设备拿到的是：

```
vm = 0xb400007d73a24410
```

注意顶上的 `0xb4`。硬件解引用时按 TBI 规则忽略顶字节，所以 `*ptr` 能正常工作——但**任何把指针当整数做的算术比较都会被这 8 位污染**：判断 `p < 0x0000_8000_0000_0000`（用户空间上界）会失败，判断链表 `next->prev == head` 时如果两个指针一个带 tag 一个不带也会假性不等。原文那套 `if (vtable < art_start || vtable > art_end)` 的区间判断，在带 tag 的指针上直接全军覆没，扫描提前夭折。

修法是在任何比较/查表之前先把指针规范化，清掉高 8 位：

```c
static inline uintptr_t canon(const void *p) {
    return (uintptr_t)p & 0x00FFFFFFFFFFFFFFULL;
}
```

链表遍历、vtable 区间判断、可读性查表，全部在去 tag 后的同一地址空间里进行。少了这一步，Android 15/16 的设备一台都跑不通。

### 坑二：mincore 对 app 进程失效

原文用 `mincore` 在解引用前判断内存页是否映射，以此防野指针 `SIGSEGV`。这个护盾在 Android 16 上自己先塌了——实测 `mincore` 对普通 app 进程返回失败，导致所有可读性判断都判否，扫描在第一步就退出，根本走不到计数。

换成解析 `/proc/self/maps` 建一张可读区间表（带 `r` 权限的段），用 syscall 直读、一次解析、按区间判断地址有效性。既不依赖 mincore，又抗 Hook（直读文件而非走 libc），还更快。顺带把区间表上限开到 8192 段——现代 App 的 maps 动辄几千行，开小了高位的 `JavaVM` 地址会落在被截断的部分之外，又是一个隐蔽的失效点。

### fail-safe 与阈值校准

定位失败（OEM 深度魔改布局、ART 版本漂移）一律返回 `-1`，上层当作"无法检查"跳过，绝不误报。阈值不拍脑袋，按实测两点定（均 fresh-process 跑 3 次稳定取值）：干净 baseline = 3，活跃注入 = 12，原文另测 LSPosed 环境 13-15。综合得干净 ≤5、注入 ≥12，安全间隔约 [6,11]，取 `DANGER = 9`——高出干净上界 4、低于注入下界 3，两侧都留余量。计数只作辅助证据，单独超过 9 才独立判危；这台 App 结构简单才敢这么用，移植到微信、手淘那种多 ClassLoader 宿主必须重新测 baseline。

---

## 四、复现流程

- **设备**：Pixel 6 Pro（raven），Android 16 / API 36，已 root（Magisk + Zygisk），装有 LSPosed。
- **被测**：Sentry v1.5，本地构建签名安装（`adb install -r -g`）。
- **注入模块**：一个 Xposed 模块 `com.cx.hook`，作用域勾选 `anti.rusda`（Sentry 包名）。LSPosed 的模块作用域配置在 `/data/adb/lspd/config/modules_config.db` 的 `scope` 表里。
- **开关**：在 LSPosed Manager 里启用/禁用该模块，分别对应注入态与干净态。模块作用域改动在目标 App **下次启动**时生效，无需重启。

每次测量都 `am force-stop anti.rusda` 起新进程，再点"开始检测"，避免缓存偏移影响。日志用 `adb logcat -s SentryTag` 抓。

---

## 五、真机验证：正负样本对照

### 干净态（LSPosed 模块禁用）

```
[CLscan] LOCKED cl_off=0x258 list_off=0x60 count=3
```

`count=3`，Xposed / Hook Framework 判 PASS，总分 95（唯一扣分项是 Bootloader 解锁，与本检测无关）。

| 概览 | 调试页 |
|:---:|:---:|
| ![clean overview](https://blog-img-1393828675.cos.ap-shanghai.myqcloud.com/sentry-classloader/clean_overview.png) | ![clean debug](https://blog-img-1393828675.cos.ap-shanghai.myqcloud.com/sentry-classloader/clean_debug.png) |

Xposed / Hook Framework 卡片明细：

```
• Xposed framework not detected (Class.forName)
• ClassLinker class_loaders_ count: 3 (offsets cl=0x258 list=0x60)
```

### 注入态（启用 `com.cx.hook`，作用域 anti.rusda）

`com.cx.hook` 注入 Sentry 进程后再扫：

```
[CLscan] LOCKED cl_off=0x258 list_off=0x60 count=12
[CLscan] located: vm_runtime_off=0x8 cl=0x258 list=0x60 count=12
```

`count` 从 3 跳到 **12**，越过阈值 9，Xposed / Hook Framework 判 DANGER，总分掉到 78。

| 概览 | 调试页 |
|:---:|:---:|
| ![lsp overview](https://blog-img-1393828675.cos.ap-shanghai.myqcloud.com/sentry-classloader/lsp_overview.png) | ![lsp debug](https://blog-img-1393828675.cos.ap-shanghai.myqcloud.com/sentry-classloader/lsp_debug.png) |

卡片明细——注意第一行：

```
• Xposed framework not detected (Class.forName)
• ClassLinker class_loaders_ count: 12 (offsets cl=0x258 list=0x60)
• Abnormally high ClassLoader count (>= 9) - strong LSPosed/injection indicator
```

### 关键对照：传统检测全被绕过，唯独计数抓到

要证明这一招的价值，得看它和"传统手段"在同一次注入下的表现差。Sentry 里检测 Xposed/Hook 的那一项，内部本就串了多条传统 Java 侧检测，把它们和 ClassLoader 计数放在同一次扫描里对照——传统手段全军覆没，只有计数命中：

| 检测手段 | 层 | LSPosed 注入下 |
|---|---|---|
| `Class.forName("…XposedBridge")` | Java | 绕过（明细：not detected） |
| 抛异常回溯堆栈找 Xposed 类 | Java | 绕过（无命中行） |
| 反射查 `findAndHookMethod` | Java | 绕过（无命中行） |
| `VMDebug.getInstancesOfClasses` 枚举 InMemoryClassLoader 实例 | Java | 绕过（无命中行） |
| `cat /proc/self/maps` 文本扫描模块名 | Java | 绕过（maps clean） |
| **ClassLinker `class_loaders_` 计数** | **Native** | **命中，count=12** |

注意第四条——`getInstancesOfClasses` 枚举 `InMemoryClassLoader` 实例，是 Java 层里理论上最接近本方案的手段，同样被 LSPosed 挡掉了（它能 Hook 掉 `VMDebug` 这个 API 的返回）。而第五条 maps 文本扫描判 PASS 的原因很直白：LSPosed 用 `InMemoryDexClassLoader` 从内存加载模块，进程 maps 里根本没有带 `cx.hook`/`lsp`/`xposed` 字样的文件映射。直接验证 Sentry 进程的 maps：

```
# grep -iE "cx.hook|lsp|xposed" /proc/<pid>/maps  →  无输出
```

文件名、API 返回值这些"可被拦截篡改"的面，LSPosed 都抹干净了。但它为了让模块跑起来，必须把模块 ClassLoader 挂上 `class_loaders_`——这条链上凭空多出来的 9 个实例（3→12）抹不掉。把检测从"问答式 API"下沉到"GC 必经的运行时内存事实"，差距就在这里。

---

## 六、剖析：为什么是降维打击，又为什么不是银弹

ClassLinker 计数能赢，根子在于它检测的对象是 **GC 必须遍历的运行时数据结构**，而不是任何形式的查询接口。Shamiko 这类隐藏方案的全部能力建立在"拦截查询、篡改返回"上——文件查询、PackageManager 查询、maps 读取，都是 App 主动问、系统被动答的模型，answer 可以被 Hook。而 `class_loaders_` 是 ART 自己在 GC 时要走的链，没有"问答"环节给攻击者插手；要让模块 ClassLoader 从链上消失，等价于让它被 GC 回收，模块自身就死了。攻击者唯一的出路是针对性逆向并 inline Hook 检测函数本身，但那是成本极高的定点打击，已经脱离"通用隐藏"的范畴。

但它也不是银弹，工程上有三条必须正视的边界：

- **宿主复杂度决定 baseline**。简单 App baseline=3，注入后 12 很显眼；但多模块、带 WebView、用 split APK 的复杂宿主，干净 baseline 本就可能十几个，阈值会和注入态重叠。计数检测必须按宿主单独校准，不能跨 App 套用同一个魔数。
- **激进的内存盲扫需要 fail-safe**。从 `Runtime` 偏移 0 扫到 0xE00、读任意候选指针，本身就是在刀尖上走。可读性探针 + 三特征校验 + 定位失败返回 -1，是保证它在千奇百怪的 OEM ROM 上"抓不到就跳过"而不是"崩给你看"的前提。
- **平台演进会搬走地基**。这次 Android 16 的 TBI 标签和 mincore 失效就是活例子——原文在 13/14 能跑的代码，到 16 一行没改就全废。任何依赖底层内存布局的检测都得跟着系统版本持续回归。

所以它的定位是"抗隐藏能力极强、但需要按宿主校准且要跟平台持续回归"的一条硬信号，不适合当唯一判据一招鲜。检测与对抗本就是螺旋上升的——当 API 层、文件层、maps 层的 Hook 已经泛滥，把战场下沉到 ART 自己都绕不开的运行时数据结构，往往能换来一个攻击者绕不动、或绕的成本远高于收益的时间窗。这正是看雪原文那条思路的价值，而把它在 Android 16 上真正落地、踩平 TBI 与 mincore 两个坑、再用真机正负样本钉死，是本文想补上的工程一环。

---

*实现细节见 [`app/src/main/cpp/detector/class_linker_scan.cpp`](../app/src/main/cpp/detector/class_linker_scan.cpp) 与 [`doc/DETECTION_SPEC.md`](DETECTION_SPEC.md) 的 D7 章节。*
