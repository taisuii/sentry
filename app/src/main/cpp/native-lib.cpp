#include <jni.h>
#include <cstdio>
#include <android/log.h>

#include "detector/thread_detector.h"
#include "detector/memory_scanner.h"
#include "detector/port_scanner.h"
#include "detector/hook_detector.h"
#include "detector/so_integrity.h"
#include "detector/art_method_detector.h"
#include "detector/trap_detector.h"
#include "detector/xposed_detector.h"
#include "detector/class_linker_scan.h"

#define MAX_MEMORY_DETAILS 16

#define LOG_TAG "SentryTag"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * 加固：JNI 函数不再用 Java_<class>_<method> 静态命名导出（那会把 native 函数名与
 * 对应 Java 方法直接暴露在 .so 动态符号表里，还逼着 Java 类名不能被混淆）。
 * 改为：实现函数全部 static + 不透明名（编译后符号被裁剪），运行时在 JNI_OnLoad
 * 里用 RegisterNatives 动态绑定。配合 version script，.so 只导出 JNI_OnLoad。
 */

/* ===== DebugDetectionManager 的 native 实现（static，不透明名） ===== */

static jobjectArray JNICALL h0(JNIEnv *env, jclass clazz) {  /* nativeDetectXposedPaths */
    char details[MAX_MEMORY_DETAILS][256];
    int n = get_xposed_path_and_fd_details(details, MAX_MEMORY_DETAILS);
    int status = (n > 0) ? 2 : 0;
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    int arrLen = 2 + (n > 0 ? n : 1);
    jobjectArray arr = env->NewObjectArray(arrLen, stringClass, nullptr);
    if (!arr) return nullptr;
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(status == 2 ? "2" : "0"));
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(n > 0 ? "Xposed-related paths or fd detected" : "No Xposed paths/fd detected"));
    if (n == 0) {
        env->SetObjectArrayElement(arr, 2, env->NewStringUTF("No Xposed path or linjector fd found"));
    } else {
        for (int i = 0; i < n; i++) {
            env->SetObjectArrayElement(arr, 2 + i, env->NewStringUTF(details[i]));
        }
    }
    return arr;
}

static jobjectArray JNICALL h1(JNIEnv *env, jclass clazz) {  /* nativeGetSoIntegrityResult */
    LOGD("[SO] check start");
    int r1 = check_libc_text_integrity();
    int r2 = detect_frida_got_hook();
    int r3 = check_frida_port();
    int r4 = scan_suspicious_anonymous_rx_memory();
    int r0 = check_critical_functions();
    int status = (r1 == 1 || r2 == 1 || r3 == 1 || r4 == 1 || r0 == 1) ? 2 : 0;
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    jobjectArray arr = env->NewObjectArray(3, stringClass, nullptr);
    if (!arr) return nullptr;
    int any_skipped = (r1 == -1 && r2 == -1);
    const char *sum = (status == 2)
            ? "Frida detected (CRC/GOT/port anomaly)"
            : (any_skipped && r3 != 1 && r4 != 1) ? "Check skipped (libc not in process)"
            : "System library integrity OK";
    const char *det = (status == 2)
            ? "libc.so modified, GOT hijacked, or Frida server detected"
            : (any_skipped && r3 != 1 && r4 != 1) ? "Check skipped"
            : "No Frida detected";
    LOGD("[SO] check end: crc=%d got=%d port=%d mem=%d critical=%d status=%d", r1, r2, r3, r4, r0, status);
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(status == 2 ? "2" : "0"));
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(sum));
    env->SetObjectArrayElement(arr, 2, env->NewStringUTF(det));
    return arr;
}

static jobjectArray JNICALL h2(JNIEnv *env, jclass clazz, jclass targetClass) {  /* nativeGetArtMethodCheckResult */
    char detailBuf[256];
    int r = art_method_check_entry_points(env, targetClass, detailBuf, sizeof(detailBuf));
    int status = (r == 1) ? 2 : 0;
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    jobjectArray arr = env->NewObjectArray(3, stringClass, nullptr);
    if (!arr) return nullptr;
    const char *summary = (r == 1) ? "Java method entry point outside libart/oat (possible Frida)"
            : (r == -1) ? "Could not perform check (maps or Activity not available)"
            : "ArtMethod entry points in expected range";
    const char *det = (r == -1 && detailBuf[0]) ? detailBuf : (r == -1) ? "Check skipped" : detailBuf;
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(status == 2 ? "2" : "0"));
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(summary));
    env->SetObjectArrayElement(arr, 2, env->NewStringUTF(det));
    return arr;
}

static jobjectArray JNICALL h3(JNIEnv *env, jclass clazz) {  /* nativeGetTrapCheckResult */
    int r = detect_trap_signal_handled();
    int status = (r == 1) ? 2 : 0;
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    jobjectArray arr = env->NewObjectArray(3, stringClass, nullptr);
    if (!arr) return nullptr;
    const char *summary = (r == 1) ? "SIGTRAP likely handled by external (e.g. Frida)"
            : (r == -1) ? "Could not perform check (signal or thread setup failed)"
            : "Signal trap check passed";
    const char *det = (r == 1) ? "Our SIGTRAP handler was not invoked"
            : (r == -1) ? "Check skipped" : "Our handler invoked as expected";
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(status == 2 ? "2" : "0"));
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(summary));
    env->SetObjectArrayElement(arr, 2, env->NewStringUTF(det));
    return arr;
}

static jobjectArray JNICALL h4(JNIEnv *env, jclass clazz) {  /* nativeDetectHook */
    bool hooked = detect_hooks();
    int status = hooked ? 2 : 0;
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    jobjectArray arr = env->NewObjectArray(3, stringClass, nullptr);
    if (!arr) return nullptr;
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(status == 2 ? "2" : "0"));
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(hooked ? "Hook/inline/PLT tampering detected" : "No hook detected"));
    env->SetObjectArrayElement(arr, 2, env->NewStringUTF(hooked ? "Critical functions appear hooked or tampered" : "PLT/GOT and libc integrity OK"));
    return arr;
}

static jobjectArray JNICALL h5(JNIEnv *env, jclass clazz, jboolean advancedChecks) {  /* nativeGetMemorySignatureResult */
    char details[MAX_MEMORY_DETAILS][256];
    int n = get_memory_signature_details_ex(details, MAX_MEMORY_DETAILS, advancedChecks ? 1 : 0);
    int status = (n > 0) ? 2 : 0;
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    int arrLen = 2 + (n > 0 ? n : 1);
    jobjectArray arr = env->NewObjectArray(arrLen, stringClass, nullptr);
    if (!arr) return nullptr;
    const char *summary = (n > 0) ? "Frida/LSPosed signatures in memory"
            : (n < 0) ? "Could not perform check (/proc/self/maps unreadable)"
            : "No Frida/LSPosed signatures in memory";
    const char *det = (n > 0) ? details[0] : (n < 0) ? "Check skipped" : "Memory scan completed - clean";
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(status == 2 ? "2" : "0"));
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(summary));
    if (n > 0) {
        for (int i = 0; i < n; i++) {
            env->SetObjectArrayElement(arr, 2 + i, env->NewStringUTF(details[i]));
        }
    } else {
        env->SetObjectArrayElement(arr, 2, env->NewStringUTF(det));
    }
    return arr;
}

static jobjectArray JNICALL h6(JNIEnv *env, jclass clazz) {  /* nativeDetectFridaThreads */
    char details[MAX_MEMORY_DETAILS][256];
    int n = get_frida_thread_details(details, MAX_MEMORY_DETAILS);
    int status = (n > 0) ? 2 : 0;
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    int arrLen = 2 + (n > 0 ? n : 1);
    jobjectArray arr = env->NewObjectArray(arrLen, stringClass, nullptr);
    if (!arr) return nullptr;
    const char *summary = (n > 0) ? "Suspicious Frida-related thread(s) detected"
            : (n < 0) ? "Could not perform check (/proc/self/task unreadable)"
            : "No suspicious threads found";
    const char *det = (n > 0) ? nullptr : (n < 0) ? "Check skipped" : "No Frida-related thread names in /proc/self/task";
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(status == 2 ? "2" : "0"));
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(summary));
    if (n > 0) {
        for (int i = 0; i < n; i++) {
            env->SetObjectArrayElement(arr, 2 + i, env->NewStringUTF(details[i]));
        }
    } else {
        env->SetObjectArrayElement(arr, 2, env->NewStringUTF(det));
    }
    return arr;
}

static jobjectArray JNICALL h7(JNIEnv *env, jclass clazz) {  /* nativeGetFridaPortScanResult */
    detect_frida_ports();
    int portCount = get_frida_port_open_count();
    int processCount = get_frida_process_detail_count();
    int dbusCount = get_frida_dbus_detail_count();
    int n = portCount + processCount + dbusCount;
    int status = (n > 0) ? 2 : 0;
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    int arrLen = 2 + (n > 0 ? n : 1);
    jobjectArray arr = env->NewObjectArray(arrLen, stringClass, nullptr);
    if (!arr) return nullptr;
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(status == 2 ? "2" : "0"));
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(n > 0 ? "Frida/IDA port(s) or Frida process(es) or D-Bus detected" : "No Frida/IDA ports or Frida processes detected"));
    if (n == 0) {
        env->SetObjectArrayElement(arr, 2, env->NewStringUTF("All Frida/IDA default ports closed, no Frida processes"));
    } else {
        int idx = 0;
        for (int i = 0; i < portCount; i++) {
            int port = get_frida_port_open_at(i);
            const char *detail;
            char buf[80];
            if (port == 0) {
                detail = "frida-server process with listening TCP (Frida 16+ random port)";
            } else if (port == 23946) {
                detail = "Port 23946 is open (IDA android_server)";
            } else {
                snprintf(buf, sizeof(buf), "Port %d is open (Frida default)", port);
                detail = buf;
            }
            env->SetObjectArrayElement(arr, 2 + idx++, env->NewStringUTF(detail));
        }
        for (int i = 0; i < processCount; i++) {
            const char *detail = get_frida_process_detail_at(i);
            if (detail) env->SetObjectArrayElement(arr, 2 + idx++, env->NewStringUTF(detail));
        }
        for (int i = 0; i < dbusCount; i++) {
            const char *detail = get_frida_dbus_detail_at(i);
            if (detail) env->SetObjectArrayElement(arr, 2 + idx++, env->NewStringUTF(detail));
        }
    }
    return arr;
}

static jintArray JNICALL h8(JNIEnv *env, jclass clazz) {  /* nativeDetectClassLoaderCount */
    int cl_off = -1, list_off = -1;
    int count = detect_classloader_count(env, &cl_off, &list_off);
    jintArray arr = env->NewIntArray(3);
    if (!arr) return nullptr;
    jint vals[3] = { (jint)count, (jint)cl_off, (jint)list_off };
    env->SetIntArrayRegion(arr, 0, 3, vals);
    return arr;
}

/* RegisterNatives 绑定表：方法名/签名仍需与 Java 侧匹配（Java 侧本就可见），
 * 但 .so 里不再有 Java_<class>_<method> 符号，函数地址需逆向 JNI_OnLoad 才能定位。 */
static const JNINativeMethod kDebugMethods[] = {
    { "nativeDetectXposedPaths",        "()[Ljava/lang/String;",                  (void *)h0 },
    { "nativeGetSoIntegrityResult",     "()[Ljava/lang/String;",                  (void *)h1 },
    { "nativeGetArtMethodCheckResult",  "(Ljava/lang/Class;)[Ljava/lang/String;", (void *)h2 },
    { "nativeGetTrapCheckResult",       "()[Ljava/lang/String;",                  (void *)h3 },
    { "nativeDetectHook",               "()[Ljava/lang/String;",                  (void *)h4 },
    { "nativeGetMemorySignatureResult", "(Z)[Ljava/lang/String;",                 (void *)h5 },
    { "nativeDetectFridaThreads",       "()[Ljava/lang/String;",                  (void *)h6 },
    { "nativeGetFridaPortScanResult",   "()[Ljava/lang/String;",                  (void *)h7 },
    { "nativeDetectClassLoaderCount",   "()[I",                                   (void *)h8 },
};

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **)&env, JNI_VERSION_1_6) != JNI_OK || !env) {
        return JNI_ERR;
    }
    jclass cls = env->FindClass("anti/rusda/detector/DebugDetectionManager");
    if (cls != nullptr) {
        int n = (int)(sizeof(kDebugMethods) / sizeof(kDebugMethods[0]));
        if (env->RegisterNatives(cls, kDebugMethods, n) != 0) {
            LOGE("RegisterNatives(DebugDetectionManager) failed");
        }
        env->DeleteLocalRef(cls);
    } else {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("FindClass(DebugDetectionManager) failed");
    }
    return JNI_VERSION_1_6;
}
