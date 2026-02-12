#include "xposed_detector.h"
#include "utils/syscall_utils.h"
#include <cstdlib>
#include <dirent.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>

#if defined(__ANDROID__)
#include <sys/system_properties.h>
#endif

#ifndef F_OK
#define F_OK 0
#endif

/* Xposed 特征路径（使用 syscall my_access 检测） */
static const char *XPOSED_PATHS[] = {
    "/system/lib/libxposed_art.so",
    "/system/lib64/libxposed_art.so",
    "/system/lib/libxposed_sandhook.so",
    "/system/lib64/libxposed_sandhook.so",
    "/data/data/de.robv.android.xposed.installer",
    nullptr
};

/* LSPosed 路径（合并自环境检测） */
static const char *LSPOSED_PATHS[] = {
    "/data/adb/lspd",
    "/data/adb/modules/zygisk_lsposed",
    nullptr
};

/* Riru 注入遗留路径 */
static const char *RIRU_PATHS[] = {
    "/system/lib64/libriruloader.so",
    "/system/lib/libriruloader.so",
    "/system/lib64/libriru.so",
    "/system/lib/libriru.so",
    nullptr
};

static bool my_strstr_wrapper(const char *haystack, const char *needle) {
    return my_strstr(haystack, needle) != nullptr;
}

static bool str_contains_ci(const char *haystack, const char *needle) {
    if (!haystack || !needle) return false;
    for (; *haystack; haystack++) {
        const char *h = haystack, *n = needle;
        while (*h && *n) {
            char ch = *h, nc = *n;
            if (ch >= 'A' && ch <= 'Z') ch += 32;
            if (nc >= 'A' && nc <= 'Z') nc += 32;
            if (ch != nc) break;
            h++; n++;
        }
        if (!*n) return true;
    }
    return false;
}

/* Native bridge 注入：LSPosed/Riru 通过 ro.dalvik.vm.native.bridge 注入 */
static bool is_suspicious_native_bridge(const char *val) {
    if (!val || !val[0]) return false;
    if (my_strcmp(val, "0") == 0) return false;
    static const char *LEGITIMATE_BRIDGES[] = {
        "houdini", "ndk-translation", "ndk_translation", "libnb", nullptr
    };
    for (int i = 0; LEGITIMATE_BRIDGES[i] != nullptr; i++) {
        if (str_contains_ci(val, LEGITIMATE_BRIDGES[i])) return false;
    }
    return str_contains_ci(val, "lspd") || str_contains_ci(val, "lsposed")
        || str_contains_ci(val, "riru") || str_contains_ci(val, "xposed");
}

int get_xposed_path_and_fd_details(char (*details)[256], int max_details) {
    int n = 0;

    /* Xposed 特征路径 */
    for (const char **p = XPOSED_PATHS; *p && n < max_details; p++) {
        if (my_access(*p, F_OK) == 0) {
            snprintf(details[n], 256, "Xposed path exists: %s", *p);
            n++;
        }
    }

    /* LSPosed 路径（合并自环境检测） */
    for (const char **p = LSPOSED_PATHS; *p && n < max_details; p++) {
        if (my_access(*p, F_OK) == 0) {
            snprintf(details[n], 256, "LSPosed path: %s", *p);
            n++;
        }
    }

    /* Riru 遗留路径 */
    for (const char **p = RIRU_PATHS; *p && n < max_details; p++) {
        if (my_access(*p, F_OK) == 0) {
            snprintf(details[n], 256, "Riru path: %s", *p);
            n++;
        }
    }

#if defined(__ANDROID__)
    /* ro.dalvik.vm.native.bridge 可疑值（Riru V26+ 注入） */
    {
        char prop_val[92];
        prop_val[0] = '\0';
#if __ANDROID_API__ >= 26
        const prop_info *pi = __system_property_find("ro.dalvik.vm.native.bridge");
        if (pi) {
            __system_property_read_callback(pi,
                [](void *cookie, const char *, const char *val, unsigned) {
                    char *dest = static_cast<char *>(cookie);
                    if (val) { my_strncpy(dest, val, 90); dest[90] = '\0'; }
                }, prop_val);
        }
#else
        if (__system_property_get("ro.dalvik.vm.native.bridge", prop_val) <= 0)
            prop_val[0] = '\0';
#endif
        if (prop_val[0] && is_suspicious_native_bridge(prop_val) && n < max_details) {
            snprintf(details[n], 256, "Suspicious native.bridge: %s", prop_val);
            n++;
        }
    }
#endif

    /* Zygisk fexecve：/proc/self/exe 为 /dev/fd/X */
    {
        char exe_path[512];
        ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (len > 0 && len < (ssize_t)sizeof(exe_path)) {
            exe_path[len] = '\0';
            if (my_strstr(exe_path, "/dev/fd/") != nullptr && n < max_details) {
                snprintf(details[n], 256, "Proc exe (Zygisk?): %s", exe_path);
                n++;
            }
        }
    }

    /* Zygisk 环境变量：LD_PRELOAD、MAGISKTMP */
    {
        const char *ld_preload = getenv("LD_PRELOAD");
        if (ld_preload && n < max_details) {
            if (my_strstr(ld_preload, "/system/bin/bu") != nullptr
                    || my_strstr(ld_preload, "/system/bin/appwidget") != nullptr) {
                snprintf(details[n], 256, "LD_PRELOAD (Zygisk): %s", ld_preload);
                n++;
            }
        }
        const char *magisk_tmp = getenv("MAGISKTMP");
        if (magisk_tmp && magisk_tmp[0] != '\0' && n < max_details) {
            snprintf(details[n], 256, "MAGISKTMP env: %s", magisk_tmp);
            n++;
        }
    }

    /* /proc/self/fd 中是否存在 linjector 等注入特征 */
    DIR *fd_dir = opendir("/proc/self/fd");
    if (fd_dir) {
        struct dirent *e;
        char link_buf[256];
        while ((e = readdir(fd_dir)) != nullptr && n < max_details) {
            if (e->d_name[0] == '.') continue;
            char path[64];
            snprintf(path, sizeof(path), "/proc/self/fd/%s", e->d_name);
            ssize_t len = readlink(path, link_buf, sizeof(link_buf) - 1);
            if (len > 0) {
                link_buf[len] = '\0';
                if (my_strstr_wrapper(link_buf, "linjector") ||
                    my_strstr_wrapper(link_buf, "lsposed") ||
                    my_strstr_wrapper(link_buf, "riru")) {
                    snprintf(details[n], 256, "Suspicious fd: %s -> %s", path, link_buf);
                    n++;
                }
            }
        }
        closedir(fd_dir);
    }

    return n;
}
