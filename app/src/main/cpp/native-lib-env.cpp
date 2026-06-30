#include <jni.h>
#include <cstring>
#include <cstdlib>
#include <string>
#include <android/log.h>
#include "detector/env_detector.h"
#include "detector/signature_checker.h"
#include "detector/apk_signature.h"

#define MAX_DETAILS 16
#define LOG_TAG "SentryTag"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * 加固：与 libantidebug 一致，JNI 实现全部 static + 不透明名，运行时 RegisterNatives
 * 动态绑定；version script 只导出 JNI_OnLoad。.so 里不再出现 Java_<class>_<method>。
 * 注意跨类：nativeDetectZygiskInjection 属于 DebugDetectionManager，
 *          nativeGetProcVersion 属于 DeviceFingerprintCollector。
 */

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

static jstring JNICALL e0(JNIEnv *env, jclass) {  /* EnvDetectionManager.nativeGetEnvVersion */
    return env->NewStringUTF("1.2");
}

static jstring JNICALL e1(JNIEnv *env, jclass) {  /* DeviceFingerprintCollector.nativeGetProcVersion */
    char *ver = env_read_proc_version();
    if (!ver) return env->NewStringUTF("");
    jstring result = env->NewStringUTF(ver);
    free(ver);
    return result;
}

static jobjectArray JNICALL e2(JNIEnv *env, jclass) {  /* nativeDetectMagisk */
    char details[MAX_DETAILS][256];
    int n = env_detect_magisk(details, MAX_DETAILS);
    int status = n > 0 ? 2 : 0;
    const char *summary = n > 0 ? "Magisk or root indicator(s) found" : "No Magisk detected";
    return buildResult(env, status, summary, details, n);
}

static jobjectArray JNICALL e3(JNIEnv *env, jclass) {  /* nativeDetectBootloader */
    char details[MAX_DETAILS][256];
    int status;
    int n = env_detect_bootloader(&status, details, MAX_DETAILS);
    const char *summary = (status == 2) ? "Bootloader unlocked or verity disabled"
        : (status == 1) ? "Bootloader state uncertain" : "Bootloader locked or unknown";
    return buildResult(env, status, summary, details, n);
}

static jobjectArray JNICALL e4(JNIEnv *env, jclass) {  /* DebugDetectionManager.nativeDetectZygiskInjection */
    char details[MAX_DETAILS][256];
    int n = env_detect_zygisk_injection(details, MAX_DETAILS);
    int status = n > 0 ? 2 : 0;
    const char *summary = n > 0 ? "Dirty page or memory injection detected"
        : "No dirty page or memory injection detected";
    return buildResult(env, status, summary, details, n);
}

static jobjectArray JNICALL e5(JNIEnv *env, jclass) {  /* nativeDetectSuspiciousFiles */
    char details[MAX_DETAILS][256];
    int n = env_detect_suspicious_files(details, MAX_DETAILS);
    int status = n > 0 ? 2 : 0;
    const char *summary = n > 0 ? "Suspicious file(s) detected" : "No suspicious files detected";
    return buildResult(env, status, summary, details, n);
}

static jboolean JNICALL e6(JNIEnv *env, jclass, jint port) {  /* nativeCheckPort */
    return env_check_port_open(static_cast<int>(port)) ? JNI_TRUE : JNI_FALSE;
}

static jobjectArray JNICALL e7(JNIEnv *env, jclass) {  /* nativeDetectAdb */
    char details[MAX_DETAILS][256];
    int n = env_detect_adb(details, MAX_DETAILS);
    int status = n > 0 ? 1 : 0;
    const char *summary = n > 0 ? "ADB/developer indicators detected (Native syscall)"
        : "No ADB indicators (Native syscall)";
    return buildResult(env, status, summary, details, n);
}

static jobjectArray JNICALL e8(JNIEnv *env, jclass) {  /* nativeCheckCgroup */
    char details[MAX_DETAILS][256];
    int n = env_detect_cgroup(details, MAX_DETAILS);
    int status = n > 0 ? 2 : 0;
    return buildResult(env, status, n > 0 ? "Container/virtualization detected" : "No container detected",
                       details, n > 0 ? n : 0);
}

static jobjectArray JNICALL e9(JNIEnv *env, jclass, jobjectArray apkPaths, jobjectArray packageNames) {  /* nativeVerifyXposedModules */
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

static jstring JNICALL e10(JNIEnv *env, jclass, jstring apkPath) {  /* nativeGetApkCertSha256FromFile */
    if (!apkPath) return env->NewStringUTF("");
    const char *path = env->GetStringUTFChars(apkPath, nullptr);
    if (!path) return env->NewStringUTF("");
    char hex[65];
    hex[0] = '\0';
    int r = apk_get_signing_cert_sha256(path, hex, sizeof(hex));
    env->ReleaseStringUTFChars(apkPath, path);
    return env->NewStringUTF(r == 0 ? hex : "");
}

static jint JNICALL e11(JNIEnv *env, jclass, jstring sha256Hex) {  /* nativeVerifyAppSignature */
    if (!sha256Hex) return 2;
    const char *hex = env->GetStringUTFChars(sha256Hex, nullptr);
    if (!hex) return 2;
    int status = verify_app_signature(hex);
    env->ReleaseStringUTFChars(sha256Hex, hex);
    return status;
}

static jobjectArray JNICALL e12(JNIEnv *env, jclass, jstring jHardware, jstring jProduct,
                                jstring jDevice, jstring jBrand) {  /* nativeDetectEmulator */
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
    const char *summary = n > 0 ? "Emulator indicator(s) found" : "Running on physical device";
    return buildResult(env, status, summary, details, n);
}

static jint JNICALL e13(JNIEnv *env, jclass, jstring apkPath) {  /* nativeApkFdInodeConsistent */
    if (!apkPath) return -1;
    const char *path = env->GetStringUTFChars(apkPath, nullptr);
    if (!path) return -1;
    int r = apk_fd_inode_consistent(path);
    env->ReleaseStringUTFChars(apkPath, path);
    return r;
}

static jint JNICALL e14(JNIEnv *env, jclass) {  /* nativeSeccompConsistent */
    return seccomp_prctl_status_consistent();
}

static const JNINativeMethod kEnvMethods[] = {
    { "nativeGetEnvVersion",            "()Ljava/lang/String;",                                                              (void *)e0 },
    { "nativeDetectMagisk",             "()[Ljava/lang/String;",                                                             (void *)e2 },
    { "nativeDetectBootloader",         "()[Ljava/lang/String;",                                                             (void *)e3 },
    { "nativeDetectSuspiciousFiles",    "()[Ljava/lang/String;",                                                             (void *)e5 },
    { "nativeCheckPort",                "(I)Z",                                                                              (void *)e6 },
    { "nativeDetectAdb",                "()[Ljava/lang/String;",                                                             (void *)e7 },
    { "nativeCheckCgroup",              "()[Ljava/lang/String;",                                                             (void *)e8 },
    { "nativeVerifyXposedModules",      "([Ljava/lang/String;[Ljava/lang/String;)[Ljava/lang/String;",                      (void *)e9 },
    { "nativeGetApkCertSha256FromFile", "(Ljava/lang/String;)Ljava/lang/String;",                                           (void *)e10 },
    { "nativeVerifyAppSignature",       "(Ljava/lang/String;)I",                                                            (void *)e11 },
    { "nativeDetectEmulator",           "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/String;", (void *)e12 },
    { "nativeApkFdInodeConsistent",     "(Ljava/lang/String;)I",                                                            (void *)e13 },
    { "nativeSeccompConsistent",        "()I",                                                                              (void *)e14 },
};
static const JNINativeMethod kDbgMethods[] = {
    { "nativeDetectZygiskInjection",    "()[Ljava/lang/String;", (void *)e4 },
};
static const JNINativeMethod kFpMethods[] = {
    { "nativeGetProcVersion",           "()Ljava/lang/String;",  (void *)e1 },
};

static void reg(JNIEnv *env, const char *cls, const JNINativeMethod *m, int n) {
    jclass c = env->FindClass(cls);
    if (c == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("FindClass(%s) failed", cls);
        return;
    }
    if (env->RegisterNatives(c, m, n) != 0) LOGE("RegisterNatives(%s) failed", cls);
    env->DeleteLocalRef(c);
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **)&env, JNI_VERSION_1_6) != JNI_OK || !env) return JNI_ERR;
    reg(env, "anti/rusda/detector/EnvDetectionManager",      kEnvMethods, (int)(sizeof(kEnvMethods) / sizeof(kEnvMethods[0])));
    reg(env, "anti/rusda/detector/DebugDetectionManager",    kDbgMethods, (int)(sizeof(kDbgMethods) / sizeof(kDbgMethods[0])));
    reg(env, "anti/rusda/detector/DeviceFingerprintCollector", kFpMethods, (int)(sizeof(kFpMethods) / sizeof(kFpMethods[0])));
    return JNI_VERSION_1_6;
}
