#include "memory_scanner.h"
#include <android/log.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define LOG_TAG "AntiFrida"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// Frida memory signatures
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
    nullptr
};

// Frida Gadget/Gadget library signatures (hex patterns)
static const unsigned char FRIDA_GADGET_SIG[] = {
    0x7f, 0x45, 0x4c, 0x46  // ELF header
};

bool detect_frida_memory_signatures(void) {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) {
        LOGD("Failed to open /proc/self/maps");
        return false;
    }

    char buffer[4096];
    ssize_t bytes_read;
    bool found_frida = false;
    char line[512];
    int line_pos = 0;

    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
        for (ssize_t i = 0; i < bytes_read; i++) {
            if (buffer[i] == '\n' || line_pos >= sizeof(line) - 1) {
                line[line_pos] = '\0';

                // Check each signature against the line
                for (int j = 0; FRIDA_SIGNATURES[j] != nullptr; j++) {
                    if (strcasestr(line, FRIDA_SIGNATURES[j]) != nullptr) {
                        LOGD("Frida signature found in maps: %s (matches: %s)",
                             line, FRIDA_SIGNATURES[j]);
                        found_frida = true;
                    }
                }
                line_pos = 0;
            } else {
                line[line_pos++] = buffer[i];
            }
        }
    }

    close(fd);
    return found_frida;
}

bool scan_maps_for_frida(void) {
    // More thorough scan of memory regions
    return detect_frida_memory_signatures();
}
