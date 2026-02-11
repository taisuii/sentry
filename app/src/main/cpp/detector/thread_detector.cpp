#include "thread_detector.h"
#include "../utils/syscall_utils.h"
#include <android/log.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define LOG_TAG "AntiFrida"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

static const char *FRIDA_THREAD_KEYWORDS[] = {
    "gmain",
    "gdbus",
    "pool-spawner",
    "frida-agent",
    "frida-gadget",
    "frida",
    "gum-js-loop",
    "gthread",
    "gpool",
    "gjs-context",
    "frida-helper",
    nullptr
};

bool detect_frida_threads(void) {
    DIR *dir = opendir("/proc/self/task");
    if (!dir) {
        LOGD("Failed to open /proc/self/task");
        return false;
    }

    struct dirent *entry;
    bool found_suspicious = false;
    char path[256];
    char buffer[256];

    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') {
            continue;
        }

        // Read thread name from comm file
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", entry->d_name);

        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            continue;
        }

        ssize_t bytes = read(fd, buffer, sizeof(buffer) - 1);
        close(fd);

        if (bytes > 0) {
            buffer[bytes] = '\0';
            // Remove newline if present
            char *newline = strchr(buffer, '\n');
            if (newline) {
                *newline = '\0';
            }

            // Check against Frida thread keywords
            for (int i = 0; FRIDA_THREAD_KEYWORDS[i] != nullptr; i++) {
                if (strcasestr(buffer, FRIDA_THREAD_KEYWORDS[i]) != nullptr) {
                    LOGD("Suspicious thread found: %s (matches: %s)",
                         buffer, FRIDA_THREAD_KEYWORDS[i]);
                    found_suspicious = true;
                    break;
                }
            }
        }
    }

    closedir(dir);
    return found_suspicious;
}
