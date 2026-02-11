#include "env_detector.h"
#include "utils/syscall_utils.h"
#include <dirent.h>
#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>

#if defined(__ANDROID__)
#include <sys/system_properties.h>
#endif

#define AF_INET      2
#define SOCK_STREAM  1
#define IPPROTO_TCP  6
#define SOL_SOCKET   1
#define SO_RCVTIMEO  20
#define SO_SNDTIMEO  21
#define CONNECT_TIMEOUT_SEC 2

struct sockaddr_in_min {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int   sin_addr;
    unsigned char  pad[8];
};

static inline unsigned short host_to_net_short(unsigned short v) {
    return (unsigned short)((v >> 8) | (v << 8));
}

/* Use syscall for file existence to bypass libc hook */
static bool file_exists(const char *path) {
    return my_access(path, F_OK) == 0;
}

static bool is_dir(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Magisk-specific paths (replaces generic su detection) */
static const char *MAGISK_PATHS[] = {
    "/data/adb/magisk",
    "/data/adb/modules",
    nullptr
};

static const char *MAGISK_HIDE_MODULE = "/data/adb/modules/zygisk_shamiko";
static const char *MAGISK_MODULES_DIR = "/data/adb/modules";

/* Check if name starts with prefix (case-sensitive) */
static bool str_starts_with(const char *str, const char *prefix) {
    if (!str || !prefix) return false;
    while (*prefix) {
        if (*str != *prefix) return false;
        str++;
        prefix++;
    }
    return true;
}

/* Suspicious files: Frida + adb paths only (no /system/xbin, /sdcard, debug_ramdisk) */
static const char *FRIDA_SCAN_DIR = "/data/local/tmp";
static const char *FRIDA_SERVER_NEEDLE = "frida-server";
static const char *FRIDA_RE_SERVER = "/data/local/tmp/re.frida.server";

static const char *SUSPICIOUS_ADB_PATHS[] = {
    "/data/adb/magisk",
    "/data/adb/modules",
    "/data/adb/lspd",
    nullptr
};

/* LSPosed paths */
static const char *LSPOSED_PATHS[] = {
    "/data/adb/lspd",
    "/data/adb/modules/zygisk_lsposed",
    nullptr
};

static const char *EMULATOR_FILES[] = {
    "/dev/socket/qemud", "/dev/qemu_pipe", "/system/lib/libc_malloc_debug_qemu.so",
    "/sys/qemu_trace", "/system/bin/qemu-props", nullptr
};

static const char *EMULATOR_INDICATORS[] = {
    "generic", "unknown", "google_sdk", "sdk", "sdk_x86", "vbox86p",
    "emulator", "simulator", "ranchu", "goldfish", nullptr
};

/* Scan directory for filenames containing needle */
static int scan_dir_for_contains(const char *dir_path, const char *needle,
                                 char (*details)[256], int max_details, int start_n) {
    DIR *d = opendir(dir_path);
    if (!d) return start_n;
    int n = start_n;
    struct dirent *e;
    while ((e = readdir(d)) != nullptr && n < max_details) {
        if (e->d_name[0] == '.') continue;
        if (my_strstr(e->d_name, needle) != nullptr) {
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", dir_path, e->d_name);
            snprintf(details[n], 256, "Found: %s", path);
            n++;
        }
    }
    closedir(d);
    return n;
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

int env_detect_magisk(char (*details)[256], int max_details) {
    int n = 0;
    for (const char **p = MAGISK_PATHS; *p && n < max_details; p++) {
        if (file_exists(*p) || is_dir(*p)) {
            snprintf(details[n], 256, "Magisk path: %s", *p);
            n++;
        }
    }
    if (file_exists(MAGISK_HIDE_MODULE) || is_dir(MAGISK_HIDE_MODULE)) {
        if (n < max_details) {
            snprintf(details[n], 256, "Shamiko (hide module) detected");
            n++;
        }
    }
    /* Zygisk: scan /data/adb/modules for zygisk_* directories */
    DIR *d = opendir(MAGISK_MODULES_DIR);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != nullptr && n < max_details) {
            if (e->d_name[0] == '.') continue;
            if (str_starts_with(e->d_name, "zygisk_")) {
                char path[512];
                snprintf(path, sizeof(path), "%s/%s", MAGISK_MODULES_DIR, e->d_name);
                if (is_dir(path)) {
                    snprintf(details[n], 256, "Zygisk module: %s", e->d_name);
                    n++;
                }
            }
        }
        closedir(d);
    }
    return n;
}

#if defined(__ANDROID__)
static void read_prop(const char *name, char *buf, size_t len) {
    buf[0] = '\0';
    if (len < 2) return;
#if __ANDROID_API__ >= 26
    const prop_info *pi = __system_property_find(name);
    if (pi) {
        __system_property_read_callback(pi,
            [](void *cookie, const char *, const char *val, unsigned) {
                char *dest = static_cast<char *>(cookie);
                if (val) {
                    strncpy(dest, val, 253);
                }
                dest[253] = '\0';
            }, buf);
    }
#else
    {
        char tmp[PROP_VALUE_MAX];
        if (__system_property_get(name, tmp) > 0) {
            strncpy(buf, tmp, len - 1);
            buf[len - 1] = '\0';
        }
    }
#endif
}
#endif

int env_detect_bootloader(int *out_status, char (*details)[256], int max_details) {
    *out_status = 0;  /* NORMAL */
    int n = 0;

#if defined(__ANDROID__)
    char state[256] = {0};
    char flash_locked[256] = {0};
    char verity_mode[256] = {0};
    char warranty_bit[256] = {0};
    char avb_version[256] = {0};

    read_prop("ro.boot.verifiedbootstate", state, sizeof(state));
    read_prop("ro.boot.flash.locked", flash_locked, sizeof(flash_locked));
    read_prop("ro.boot.veritymode", verity_mode, sizeof(verity_mode));
    read_prop("ro.boot.warranty_bit", warranty_bit, sizeof(warranty_bit));
    read_prop("ro.boot.avb_version", avb_version, sizeof(avb_version));

    if (n < max_details) {
        snprintf(details[n], 256, "verifiedbootstate: %s", state[0] ? state : "(empty)");
        n++;
    }
    if (n < max_details) {
        snprintf(details[n], 256, "flash.locked: %s", flash_locked[0] ? flash_locked : "(empty)");
        n++;
    }
    if (n < max_details) {
        snprintf(details[n], 256, "veritymode: %s", verity_mode[0] ? verity_mode : "(empty)");
        n++;
    }
    if (n < max_details) {
        snprintf(details[n], 256, "warranty_bit: %s", warranty_bit[0] ? warranty_bit : "(empty)");
        n++;
    }
    if (n < max_details) {
        snprintf(details[n], 256, "avb_version: %s", avb_version[0] ? avb_version : "(empty)");
        n++;
    }

    /* orange = DANGER */
    if (my_strstr(state, "orange") || my_strstr(state, "Orange")) {
        if (n < max_details) {
            snprintf(details[n], 256, "Bootloader unlocked (orange state)");
            n++;
        }
        *out_status = 2;  /* DANGER */
        return n;
    }
    /* flash.locked=0 = DANGER */
    if (flash_locked[0] == '0' && flash_locked[1] == '\0') {
        if (n < max_details) {
            snprintf(details[n], 256, "Flash unlocked (flash.locked=0)");
            n++;
        }
        *out_status = 2;  /* DANGER */
        return n;
    }
    /* veritymode=disabled = DANGER */
    if (my_strstr(verity_mode, "disabled") || my_strstr(verity_mode, "Disabled")) {
        if (n < max_details) {
            snprintf(details[n], 256, "Verity disabled");
            n++;
        }
        *out_status = 2;  /* DANGER */
        return n;
    }

    /* Deep checks: WARNING only (some OEMs do not support these) */
    if (warranty_bit[0] == '1' && warranty_bit[1] == '\0') {
        if (n < max_details) {
            snprintf(details[n], 256, "Warranty bit set (Samsung warranty void)");
            n++;
        }
        if (*out_status < 1) *out_status = 1;  /* WARNING */
    }
    if (!avb_version[0] || (my_strcmp(avb_version, "1.0") == 0)) {
        if (n < max_details) {
            snprintf(details[n], 256, "AVB version missing or outdated (1.0)");
            n++;
        }
        if (*out_status < 1) *out_status = 1;  /* WARNING */
    }
    return n;
#else
    snprintf(details[0], 256, "Cannot read properties (non-Android build)");
    return 1;
#endif
}

#define PROC_VERSION_MAX 512

char *env_read_proc_version(void) {
    int fd = my_open("/proc/version", 0, 0);  /* O_RDONLY */
    if (fd < 0) return nullptr;
    char *buf = static_cast<char *>(malloc(PROC_VERSION_MAX + 1));
    if (!buf) {
        my_close(fd);
        return nullptr;
    }
    ssize_t n = my_read(fd, buf, PROC_VERSION_MAX);
    my_close(fd);
    if (n <= 0) {
        free(buf);
        return nullptr;
    }
    buf[n < PROC_VERSION_MAX ? n : PROC_VERSION_MAX] = '\0';
    return buf;
}

int env_detect_lsposed(char (*details)[256], int max_details) {
    int n = 0;
    for (const char **p = LSPOSED_PATHS; *p && n < max_details; p++) {
        if (file_exists(*p) || is_dir(*p)) {
            snprintf(details[n], 256, "LSPosed path: %s", *p);
            n++;
        }
    }
    return n;
}

int env_detect_suspicious_files(char (*details)[256], int max_details) {
    int n = 0;

    /* Frida: scan /data/local/tmp for frida-server* */
    if (is_dir(FRIDA_SCAN_DIR)) {
        n = scan_dir_for_contains(FRIDA_SCAN_DIR, FRIDA_SERVER_NEEDLE, details, max_details, n);
    }

    /* Frida: re.frida.server */
    if (file_exists(FRIDA_RE_SERVER) && n < max_details) {
        snprintf(details[n], 256, "Found: %s", FRIDA_RE_SERVER);
        n++;
    }

    /* adb/magisk/modules/lspd paths */
    for (const char **p = SUSPICIOUS_ADB_PATHS; *p && n < max_details; p++) {
        if (file_exists(*p) || is_dir(*p)) {
            snprintf(details[n], 256, "Suspicious path: %s", *p);
            n++;
        }
    }
    return n;
}

int env_detect_emulator_files(const char *hardware, const char *product,
                              const char *device, const char *brand,
                              char (*details)[256], int max_details) {
    int n = 0;
    for (const char **ind = EMULATOR_INDICATORS; *ind && n < max_details; ind++) {
        if ((hardware && str_contains_ci(hardware, *ind)) ||
            (product && str_contains_ci(product, *ind)) ||
            (device && str_contains_ci(device, *ind)) ||
            (brand && str_contains_ci(brand, *ind))) {
            snprintf(details[n], 256, "Indicator in build: %s", *ind);
            n++;
        }
    }
    for (const char **p = EMULATOR_FILES; *p && n < max_details; p++) {
        if (file_exists(*p)) {
            snprintf(details[n], 256, "Emulator file: %s", *p);
            n++;
        }
    }
    if (file_exists("/data/misc/emu/update_check.cfg") && n < max_details) {
        snprintf(details[n], 256, "BlueStacks configuration detected");
        n++;
    }
    return n;
}

bool env_check_port_open(int port) {
    int sock = my_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return false;

    struct {
        long tv_sec;
        long tv_usec;
    } tv;
    tv.tv_sec = CONNECT_TIMEOUT_SEC;
    tv.tv_usec = 0;
    my_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, (unsigned int)sizeof(tv));
    my_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, (unsigned int)sizeof(tv));

    struct sockaddr_in_min addr;
    my_memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = host_to_net_short((unsigned short)port);
    addr.sin_addr   = 0x0100007f; /* 127.0.0.1 network byte order */

    int result = my_connect(sock, &addr, (unsigned int)sizeof(addr));
    my_close(sock);
    return (result == 0);
}

int env_detect_cgroup(char (*details)[256], int max_details) {
    int n = 0;
    int fd = my_open("/proc/1/cgroup", 0, 0);  /* O_RDONLY */
    if (fd < 0) return 0;

    char buffer[4096];
    ssize_t len = my_read(fd, buffer, sizeof(buffer) - 1);
    my_close(fd);
    if (len <= 0) return 0;

    buffer[len] = '\0';

    if (my_strstr(buffer, "lxc") != nullptr) {
        if (n < max_details) {
            snprintf(details[n], 256, "Container detected: lxc");
            n++;
        }
    }
    if (my_strstr(buffer, "docker") != nullptr) {
        if (n < max_details) {
            snprintf(details[n], 256, "Container detected: docker");
            n++;
        }
    }
    if (my_strstr(buffer, "kubepods") != nullptr) {
        if (n < max_details) {
            snprintf(details[n], 256, "Container detected: kubepods");
            n++;
        }
    }
    return n;
}
