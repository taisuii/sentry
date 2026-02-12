#include "xposed_detector.h"
#include "utils/syscall_utils.h"
#include <dirent.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>

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

static bool my_strstr_wrapper(const char *haystack, const char *needle) {
    return my_strstr(haystack, needle) != nullptr;
}

int get_xposed_path_and_fd_details(char (*details)[256], int max_details) {
    int n = 0;

    for (const char **p = XPOSED_PATHS; *p && n < max_details; p++) {
        if (my_access(*p, F_OK) == 0) {
            snprintf(details[n], 256, "Xposed path exists: %s", *p);
            n++;
        }
    }

    /* /proc/self/fd 中是否存在 linjector 等注入特征（frida/LSPosed 等注入工具） */
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
