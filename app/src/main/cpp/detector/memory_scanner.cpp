#include "memory_scanner.h"
#include "../utils/syscall_utils.h"
#include <android/log.h>
#include <fcntl.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define LOG_TAG "AntiFrida"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// Frida + LSPosed + Xposed + Riru + Zygisk memory signatures (use syscall to bypass libc hook)
static const char *FRIDA_SIGNATURES[] = {
    "frida",
    "FRIDA",
    "gum-js",
    "gumjs",
    "gthread",
    "gobject",
    "gmain",
    "gdbus",
    "frida-agent",
    "frida-gadget",
    "frida-server",
    "liblspd.so",
    "libriru.so",
    "libriruloader.so",
    /* Xposed / LSPosed / EdXposed */
    "libxposed",
    "xposed_art",
    "xposed_bridge",
    "XposedBridge",
    "XposedHelpers",
    "xposed.installer",
    "XposedBridge.jar",
    "de.robv.android.xposed",
    "org.lsposed",
    nullptr
};

#define MAX_MEMORY_FINDINGS 16
static char s_findings[MAX_MEMORY_FINDINGS][256];
static int s_finding_count = 0;

/* 匿名可执行内存：LSPosed 隐藏 so 时仍保留可执行权限，阈值 128KB 降低 JIT 误报 */
#define ANON_EXEC_SIZE_THRESHOLD (128 * 1024)
#define MAX_ANON_EXEC_FINDINGS 2

static bool has_exec_perm(const char *perms) {
    if (!perms) return false;
    for (int i = 0; i < 4 && perms[i]; i++) {
        if (perms[i] == 'x') return true;
    }
    return false;
}

static bool is_anon_path(const char *path) {
    if (!path || !path[0]) return true;
    if (path[0] == '/') return false;  /* 文件路径 */
    if (path[0] == '[') {
        const char *skip[] = { "[vdso]", "[vvar]", "[stack]", "[heap]", nullptr };
        for (int i = 0; skip[i]; i++) {
            const char *s = path, *t = skip[i];
            while (*s && *t && (*s == *t || (*s >= 'A' && *s <= 'Z' && *s + 32 == *t))) s++, t++;
            if (!*t && (*s == ']' || *s == '\0')) return false;  /* 已知良性 */
        }
        return true;  /* [anon:xxx] 等 */
    }
    return true;  /* 其他无名 */
}

static void check_anon_exec_memory(const char *line, char (*findings)[256], int max_findings,
                                   int *count, int *anon_count) {
    if (*anon_count >= MAX_ANON_EXEC_FINDINGS) return;
    unsigned long start = 0, end = 0;
    char perms[8] = {0};
    char path[384] = {0};
    if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %383s", &start, &end, perms, path) < 3)
        return;
    size_t size = end - start;
    if (size < ANON_EXEC_SIZE_THRESHOLD || !has_exec_perm(perms) || !is_anon_path(path))
        return;
    if (*count < max_findings) {
        snprintf(findings[*count], 256, "Anonymous executable memory: %lx-%lx (size: %zu KB)",
                 start, end, size / 1024);
        (*count)++;
        (*anon_count)++;
    }
}

int get_memory_signature_details(char (*details)[256], int max_details) {
    s_finding_count = 0;
    int anon_exec_count = 0;
    int fd = my_open("/proc/self/maps", 0, 0);  /* O_RDONLY */
    if (fd < 0) {
        LOGD("Failed to open /proc/self/maps");
        return 0;
    }

    char buffer[4096];
    ssize_t bytes_read;
    char line[512];
    int line_pos = 0;

    while ((bytes_read = my_read(fd, buffer, sizeof(buffer))) > 0) {
        for (ssize_t i = 0; i < bytes_read && s_finding_count < max_details; i++) {
            if (buffer[i] == '\n' || line_pos >= sizeof(line) - 1) {
                line[line_pos] = '\0';

                for (int j = 0; FRIDA_SIGNATURES[j] != nullptr && s_finding_count < max_details; j++) {
                    if (my_strcasestr(line, FRIDA_SIGNATURES[j]) != nullptr) {
                        LOGD("Frida signature found in maps: %s (matches: %s)",
                             line, FRIDA_SIGNATURES[j]);
                        snprintf(s_findings[s_finding_count], 256,
                                 "Found '%s' in: %s", FRIDA_SIGNATURES[j], line);
                        s_finding_count++;
                        break;
                    }
                }
                /* 匿名可执行内存：LSPosed 隐藏 so 时仍保留可执行权限 */
                check_anon_exec_memory(line, s_findings, MAX_MEMORY_FINDINGS, &s_finding_count, &anon_exec_count);

                line_pos = 0;
            } else {
                line[line_pos++] = buffer[i];
            }
        }
    }

    my_close(fd);
    if (details) {
        for (int i = 0; i < s_finding_count && i < max_details; i++) {
            snprintf(details[i], 256, "%s", s_findings[i]);
        }
    }
    return s_finding_count;
}

bool detect_frida_memory_signatures(void) {
    char dummy[1][256];
    return get_memory_signature_details(dummy, 1) > 0;
}

bool scan_maps_for_frida(void) {
    return detect_frida_memory_signatures();
}
