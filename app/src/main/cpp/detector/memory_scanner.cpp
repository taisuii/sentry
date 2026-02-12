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

// Frida + LSPosed + Xposed memory signatures (use syscall to bypass libc hook)
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

int get_memory_signature_details(char (*details)[256], int max_details) {
    s_finding_count = 0;
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
