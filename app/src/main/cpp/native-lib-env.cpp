#include <jni.h>
#include <cstring>
#include <string>
#include "detector/env_detector.h"

#define MAX_DETAILS 16

static jobjectArray buildResult(JNIEnv *env, int status, const char *summary,
                                char (*details)[256], int detail_count) {
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    int arrLen = 2 + (detail_count > 0 ? detail_count : 1);
    jobjectArray arr = env->NewObjectArray(arrLen, stringClass, nullptr);
    if (!arr) return nullptr;

    char statusStr[8];
    snprintf(statusStr, sizeof(statusStr), "%d", status);
    env->SetObjectArrayElement(arr, 0, env->NewStringUTF(statusStr));
    env->SetObjectArrayElement(arr, 1, env->NewStringUTF(summary));

    if (detail_count <= 0) {
        env->SetObjectArrayElement(arr, 2, env->NewStringUTF("No issues detected"));
    } else {
        for (int i = 0; i < detail_count; i++) {
            env->SetObjectArrayElement(arr, 2 + i, env->NewStringUTF(details[i]));
        }
    }
    return arr;
}

extern "C" {

JNIEXPORT jstring JNICALL
Java_anti_rusda_detector_EnvDetectionManager_nativeGetEnvVersion(JNIEnv *env, jclass clazz) {
    return env->NewStringUTF("1.2");
}

JNIEXPORT jstring JNICALL
Java_anti_rusda_detector_DeviceFingerprintCollector_nativeGetProcVersion(JNIEnv *env, jclass clazz) {
    char *ver = env_read_proc_version();
    if (!ver) return env->NewStringUTF("");
    jstring result = env->NewStringUTF(ver);
    free(ver);
    return result;
}

// Magisk detection: returns String[] { status, summary, detail0, ... }; status 2 = DANGER
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_EnvDetectionManager_nativeDetectMagisk(JNIEnv *env, jclass clazz) {
    char details[MAX_DETAILS][256];
    int n = env_detect_magisk(details, MAX_DETAILS);
    int status = n > 0 ? 2 : 0;  // 2 = DANGER
    const char *summary = n > 0
        ? "Magisk or root indicator(s) found"
        : "No Magisk detected";
    return buildResult(env, status, summary, details, n);
}

// Bootloader: returns String[] { status, summary, ... }; status 2 = DANGER
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_EnvDetectionManager_nativeDetectBootloader(JNIEnv *env, jclass clazz) {
    char details[MAX_DETAILS][256];
    int status;
    int n = env_detect_bootloader(&status, details, MAX_DETAILS);
    const char *summary = (status == 2)
        ? "Bootloader unlocked or verity disabled"
        : (status == 1)
            ? "Bootloader state uncertain"
            : "Bootloader locked or unknown";
    return buildResult(env, status, summary, details, n);
}

// LSPosed: returns String[] { status, summary, ... }; status 2 = DANGER
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_EnvDetectionManager_nativeDetectLsposed(JNIEnv *env, jclass clazz) {
    char details[MAX_DETAILS][256];
    int n = env_detect_lsposed(details, MAX_DETAILS);
    int status = n > 0 ? 2 : 0;  // 2 = DANGER
    const char *summary = n > 0
        ? "LSPosed framework detected"
        : "No LSPosed detected";
    return buildResult(env, status, summary, details, n);
}

// Suspicious files: returns String[] { status, summary, ... }; status 2 = DANGER
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_EnvDetectionManager_nativeDetectSuspiciousFiles(JNIEnv *env, jclass clazz) {
    char details[MAX_DETAILS][256];
    int n = env_detect_suspicious_files(details, MAX_DETAILS);
    int status = n > 0 ? 2 : 0;
    const char *summary = n > 0
        ? "Suspicious file(s) detected"
        : "No suspicious files detected";
    return buildResult(env, status, summary, details, n);
}

// Port check for ADB 5555 etc. (uses syscall)
JNIEXPORT jboolean JNICALL
Java_anti_rusda_detector_EnvDetectionManager_nativeCheckPort(JNIEnv *env, jclass clazz, jint port) {
    return env_check_port_open(static_cast<int>(port)) ? JNI_TRUE : JNI_FALSE;
}

// Cgroup container check: returns String[] { status, detail }
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_EnvDetectionManager_nativeCheckCgroup(JNIEnv *env, jclass clazz) {
    char details[MAX_DETAILS][256];
    int n = env_detect_cgroup(details, MAX_DETAILS);
    int status = n > 0 ? 2 : 0;  /* 2 = DANGER */
    const char *detail = n > 0 ? details[0] : "";
    return buildResult(env, status, n > 0 ? "Container/virtualization detected" : "No container detected", details, n > 0 ? n : 0);
}

// Emulator: Java passes Build.*; native checks files + indicators
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_EnvDetectionManager_nativeDetectEmulator(JNIEnv *env, jclass clazz,
        jstring jHardware, jstring jProduct, jstring jDevice, jstring jBrand) {
    const char *hardware = jHardware ? env->GetStringUTFChars(jHardware, nullptr) : "";
    const char *product = jProduct ? env->GetStringUTFChars(jProduct, nullptr) : "";
    const char *device = jDevice ? env->GetStringUTFChars(jDevice, nullptr) : "";
    const char *brand = jBrand ? env->GetStringUTFChars(jBrand, nullptr) : "";

    char details[MAX_DETAILS][256];
    int n = env_detect_emulator_files(hardware, product, device, brand, details, MAX_DETAILS);

    if (jHardware) env->ReleaseStringUTFChars(jHardware, hardware);
    if (jProduct) env->ReleaseStringUTFChars(jProduct, product);
    if (jDevice) env->ReleaseStringUTFChars(jDevice, device);
    if (jBrand) env->ReleaseStringUTFChars(jBrand, brand);

    int status = n > 0 ? 1 : 0;
    const char *summary = n > 0
        ? "Emulator indicator(s) found"
        : "Running on physical device";
    return buildResult(env, status, summary, details, n);
}

} // extern "C"
