#include <jni.h>
#include <cstring>
#include <string>
#include "detector/env_detector.h"
#include "detector/signature_checker.h"
#include "detector/apk_signature.h"

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

// Dirty page / memory injection (Debug tab): Smaps Private_Dirty + VMap + Pagemap bit 55; returns String[] { status, summary, ... }
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_DebugDetectionManager_nativeDetectZygiskInjection(JNIEnv *env, jclass clazz) {
    char details[MAX_DETAILS][256];
    int n = env_detect_zygisk_injection(details, MAX_DETAILS);
    int status = n > 0 ? 2 : 0;  // 2 = DANGER
    const char *summary = n > 0
        ? "Dirty page or memory injection detected"
        : "No dirty page or memory injection detected";
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

// ADB detection: multi-channel Native (syscall), returns String[] { status, summary, detail0, ... }
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_EnvDetectionManager_nativeDetectAdb(JNIEnv *env, jclass clazz) {
    char details[MAX_DETAILS][256];
    int n = env_detect_adb(details, MAX_DETAILS);
    int status = n > 0 ? 1 : 0;  /* 1 = WARNING */
    const char *summary = n > 0
        ? "ADB/developer indicators detected (Native syscall)"
        : "No ADB indicators (Native syscall)";
    return buildResult(env, status, summary, details, n);
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

// Dangerous Apps: verify APKs via syscall (assets/xposed_init) + modules.list; returns String[] of package names
JNIEXPORT jobjectArray JNICALL
Java_anti_rusda_detector_EnvDetectionManager_nativeVerifyXposedModules(JNIEnv *env, jclass clazz,
        jobjectArray apkPaths, jobjectArray packageNames) {
    if (!apkPaths || !packageNames) return nullptr;
    jsize count = env->GetArrayLength(apkPaths);
    if (count != env->GetArrayLength(packageNames) || count <= 0) return nullptr;

    const char *paths[256];
    const char *pkgs[256];
    char *pathChars[256];
    char *pkgChars[256];
    jsize copyCount = count > 256 ? 256 : count;

    jstring jPathArr[256], jPkgArr[256];
    for (jsize i = 0; i < copyCount; i++) {
        jstring jPath = (jstring)env->GetObjectArrayElement(apkPaths, i);
        jstring jPkg = (jstring)env->GetObjectArrayElement(packageNames, i);
        jPathArr[i] = jPath;
        jPkgArr[i] = jPkg;
        pathChars[i] = jPath ? const_cast<char *>(env->GetStringUTFChars(jPath, nullptr)) : nullptr;
        pkgChars[i] = jPkg ? const_cast<char *>(env->GetStringUTFChars(jPkg, nullptr)) : nullptr;
        paths[i] = pathChars[i];
        pkgs[i] = pkgChars[i];
    }

    char outPkgs[32][256];
    int n = env_verify_xposed_modules(paths, pkgs, copyCount, outPkgs, 32);

    for (jsize i = 0; i < copyCount; i++) {
        if (pathChars[i] && jPathArr[i]) env->ReleaseStringUTFChars(jPathArr[i], pathChars[i]);
        if (pkgChars[i] && jPkgArr[i]) env->ReleaseStringUTFChars(jPkgArr[i], pkgChars[i]);
    }

    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;
    jobjectArray result = env->NewObjectArray(n, stringClass, nullptr);
    if (!result) return nullptr;
    for (int i = 0; i < n; i++) {
        env->SetObjectArrayElement(result, i, env->NewStringUTF(outPkgs[i]));
    }
    return result;
}

// APK file-level signing cert SHA-256 (anti-repackage + anti signature-spoof):
// parses v2/v3 signing block directly from the APK file via syscall, bypassing
// PackageManager (which CorePatch/fake-signature modules can hook). Returns
// 64-hex lowercase, or "" on failure.
JNIEXPORT jstring JNICALL
Java_anti_rusda_detector_EnvDetectionManager_nativeGetApkCertSha256FromFile(JNIEnv *env, jclass clazz, jstring apkPath) {
    if (!apkPath) return env->NewStringUTF("");
    const char *path = env->GetStringUTFChars(apkPath, nullptr);
    if (!path) return env->NewStringUTF("");
    char hex[65];
    hex[0] = '\0';
    int r = apk_get_signing_cert_sha256(path, hex, sizeof(hex));
    env->ReleaseStringUTFChars(apkPath, path);
    return env->NewStringUTF(r == 0 ? hex : "");
}

// App signature verification (anti-repackage): current SHA-256 hex from Java, compare with build-time expected
JNIEXPORT jint JNICALL
Java_anti_rusda_detector_EnvDetectionManager_nativeVerifyAppSignature(JNIEnv *env, jclass clazz, jstring sha256Hex) {
    if (!sha256Hex) return 2;
    const char *hex = env->GetStringUTFChars(sha256Hex, nullptr);
    if (!hex) return 2;
    int status = verify_app_signature(hex);
    env->ReleaseStringUTFChars(sha256Hex, hex);
    return status;
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
