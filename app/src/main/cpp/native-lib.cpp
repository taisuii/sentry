#include <jni.h>
#include <string>
#include <android/log.h>

#include "detector/thread_detector.h"
#include "detector/memory_scanner.h"
#include "detector/port_scanner.h"
#include "detector/hook_detector.h"
#include "detector/xposed_detector.h"
#include "detector/anti_debug.h"

#define MAX_MEMORY_DETAILS 16

#define LOG_TAG "AntiFrida"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C" {

// Xposed path/fd detection: String[] { status, summary, detail0, ... }; uses syscall for paths
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_DebugDetectionManager_nativeDetectXposedPaths(JNIEnv *env, jclass clazz) {
    char details[MAX_MEMORY_DETAILS][256];
    int n = get_xposed_path_and_fd_details(details, MAX_MEMORY_DETAILS);
    int status = (n > 0) ? 2 : 0;  /* 2 = DANGER, 0 = NORMAL */
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

// Hook detection for Java: String[] { status, summary, detail }; enhances Xposed detection
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_DebugDetectionManager_nativeDetectHook(JNIEnv *env, jclass clazz) {
    bool hooked = detect_hooks();
    int status = hooked ? 2 : 0;  /* 2 = DANGER, 0 = NORMAL */
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    jobjectArray arr = env->NewObjectArray(3, stringClass, nullptr);
    if (!arr) return nullptr;
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(status == 2 ? "2" : "0"));
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(hooked ? "Hook/inline/PLT tampering detected" : "No hook detected"));
    env->SetObjectArrayElement(arr, 2, env->NewStringUTF(hooked ? "Critical functions appear hooked or tampered" : "PLT/GOT and libc integrity OK"));
    return arr;
}

// Memory signature result for Java: String[] { status, summary, detail0, ... } (uses syscall)
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_DebugDetectionManager_nativeGetMemorySignatureResult(JNIEnv *env, jclass clazz) {
    char details[MAX_MEMORY_DETAILS][256];
    int n = get_memory_signature_details(details, MAX_MEMORY_DETAILS);
    int status = (n > 0) ? 2 : 0;  // 2 = DANGER, 0 = NORMAL
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    int arrLen = 2 + (n > 0 ? n : 1);
    jobjectArray arr = env->NewObjectArray(arrLen, stringClass, nullptr);
    if (!arr) return nullptr;
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(status == 2 ? "2" : "0"));
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(n > 0 ? "Frida/LSPosed signatures in memory" : "No Frida/LSPosed signatures in memory"));
    if (n == 0) {
        env->SetObjectArrayElement(arr, 2, env->NewStringUTF("Memory scan completed - clean"));
    } else {
        for (int i = 0; i < n; i++) {
            env->SetObjectArrayElement(arr, 2 + i, env->NewStringUTF(details[i]));
        }
    }
    return arr;
}

// Frida thread detection for Java: String[] { status, summary, detail0, ... }; uses syscall
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_DebugDetectionManager_nativeDetectFridaThreads(JNIEnv *env, jclass clazz) {
    char details[MAX_MEMORY_DETAILS][256];
    int n = get_frida_thread_details(details, MAX_MEMORY_DETAILS);
    int status = (n > 0) ? 2 : 0;  /* 2 = DANGER, 0 = NORMAL */
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    int arrLen = 2 + (n > 0 ? n : 1);
    jobjectArray arr = env->NewObjectArray(arrLen, stringClass, nullptr);
    if (!arr) return nullptr;
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(status == 2 ? "2" : "0"));
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(n > 0 ? "Suspicious Frida-related thread(s) detected" : "No suspicious threads found"));
    if (n == 0) {
        env->SetObjectArrayElement(arr, 2, env->NewStringUTF("No Frida-related thread names in /proc/self/task"));
    } else {
        for (int i = 0; i < n; i++) {
            env->SetObjectArrayElement(arr, 2 + i, env->NewStringUTF(details[i]));
        }
    }
    return arr;
}

// Port scan result for Java: String[] { status, summary, detail0, detail1, ... }
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_DebugDetectionManager_nativeGetFridaPortScanResult(JNIEnv *env, jclass clazz) {
    detect_frida_ports();
    int n = get_frida_port_open_count();
    int status = (n > 0) ? 2 : 0;  // 2 = DANGER, 0 = NORMAL
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    int arrLen = 2 + (n > 0 ? n : 1);  // status, summary, then n details or 1 "All closed"
    jobjectArray arr = env->NewObjectArray(arrLen, stringClass, nullptr);
    if (!arr) return nullptr;
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(status == 2 ? "2" : "0"));
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(n > 0 ? "Frida port(s) detected" : "No Frida ports detected"));
    if (n == 0) {
        env->SetObjectArrayElement(arr, 2, env->NewStringUTF("All Frida default ports are closed"));
    } else {
        for (int i = 0; i < n; i++) {
            int port = get_frida_port_open_at(i);
            const char *detail;
            char buf[64];
            if (port == 0) {
                detail = "frida-server process with listening TCP (Frida 16+ random port)";
            } else {
                snprintf(buf, sizeof(buf), "Port %d is open (Frida default)", port);
                detail = buf;
            }
            env->SetObjectArrayElement(arr, 2 + i, env->NewStringUTF(detail));
        }
    }
    return arr;
}

// Thread detection
JNIEXPORT jboolean JNICALL
Java_anti_rusda_MainActivity_nativeDetectFridaThread(JNIEnv *env, jobject thiz) {
    LOGD("Starting Frida thread detection...");
    return detect_frida_threads() ? JNI_TRUE : JNI_FALSE;
}

// Port detection
JNIEXPORT jboolean JNICALL
Java_anti_rusda_MainActivity_nativeDetectFridaPort(JNIEnv *env, jobject thiz) {
    LOGD("Starting Frida port detection...");
    return detect_frida_ports() ? JNI_TRUE : JNI_FALSE;
}

// Memory signature detection
JNIEXPORT jboolean JNICALL
Java_anti_rusda_MainActivity_nativeDetectFridaMemory(JNIEnv *env, jobject thiz) {
    LOGD("Starting Frida memory signature detection...");
    return detect_frida_memory_signatures() ? JNI_TRUE : JNI_FALSE;
}

// Debug mode detection
JNIEXPORT jboolean JNICALL
Java_anti_rusda_MainActivity_nativeDetectDebugMode(JNIEnv *env, jobject thiz) {
    LOGD("Starting debug mode detection...");
    return detect_debug_mode() ? JNI_TRUE : JNI_FALSE;
}

// Hook detection
JNIEXPORT jboolean JNICALL
Java_anti_rusda_MainActivity_nativeDetectHook(JNIEnv *env, jobject thiz) {
    LOGD("Starting hook detection...");
    return detect_hooks() ? JNI_TRUE : JNI_FALSE;
}

// Get detailed detection info
JNIEXPORT jstring JNICALL
Java_anti_rusda_MainActivity_nativeGetDetectionDetails(JNIEnv *env, jobject thiz) {
    std::string details = "Detection Details:\n\n";

    details += "Thread Detection: ";
    details += detect_frida_threads() ? "SUSPICIOUS\n" : "CLEAN\n";

    details += "Port Detection: ";
    details += detect_frida_ports() ? "SUSPICIOUS\n" : "CLEAN\n";

    details += "Memory Signature: ";
    details += detect_frida_memory_signatures() ? "SUSPICIOUS\n" : "CLEAN\n";

    details += "Debug Mode: ";
    details += detect_debug_mode() ? "SUSPICIOUS\n" : "CLEAN\n";

    details += "Hook Detection: ";
    details += detect_hooks() ? "SUSPICIOUS\n" : "CLEAN\n";

    return env->NewStringUTF(details.c_str());
}

} // extern "C"
