#include <jni.h>
#include <string>
#include <android/log.h>

#include "detector/thread_detector.h"
#include "detector/memory_scanner.h"
#include "detector/port_scanner.h"
#include "detector/hook_detector.h"
#include "detector/anti_debug.h"

#define LOG_TAG "AntiFrida"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C" {

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
