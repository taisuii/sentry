#include "env_detector.h"
#include "utils/syscall_utils.h"
#include <dirent.h>
#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <cerrno>
#include <sys/socket.h>

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

/* ZIP local file header: 0x04034b50, then at 0x1A filename_len (2 bytes), 0x1C extra_len (2 bytes) */
#define ZIP_LOCAL_SIG 0x04034b50
#define ZIP_HEADER_FIXED 30

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

/* Zygisk 特征字符串（VMap 内存扫描） */
static const char *ZYGISK_SIGNATURES[] = {
    "zygisk_module_entry",
    "libzygisk.so",
    "ZygiskModule",
    "zygisk",
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

/* Cross-verify prop value with /proc/cmdline to detect __system_property_get hook */
static bool extract_cmdline_value(const char *cmdline, size_t len, const char *key, char *out, size_t out_len) {
    if (!cmdline || !key || !out || out_len < 2) return false;
    out[0] = '\0';
    size_t key_len = my_strlen(key);
    const char *p = cmdline;
    while (p < cmdline + len) {
        if (my_strncmp(p, key, key_len) == 0 && p[key_len] == '=') {
            const char *val = p + key_len + 1;
            size_t i = 0;
            while (val + i < cmdline + len && val[i] && val[i] != ' ' && i < out_len - 1) {
                out[i] = val[i];
                i++;
            }
            out[i] = '\0';
            return i > 0;
        }
        while (p < cmdline + len && *p && *p != ' ') p++;
        if (p < cmdline + len && *p == ' ') p++;
    }
    return false;
}

static bool verify_prop_vs_cmdline(const char *prop_val, const char *cmdline_key, char *cmdline_buf, size_t cmdline_len) {
    char cmdline_val[64] = {0};
    if (!extract_cmdline_value(cmdline_buf, cmdline_len, cmdline_key, cmdline_val, sizeof(cmdline_val)))
        return true;  /* no cmdline value, assume ok */
    if (!prop_val || !prop_val[0]) return true;
    return my_strcmp(prop_val, cmdline_val) == 0;
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
    char vbmeta_state[256] = {0};
    char oem_unlock[256] = {0};

    read_prop("ro.boot.verifiedbootstate", state, sizeof(state));
    read_prop("ro.boot.flash.locked", flash_locked, sizeof(flash_locked));
    read_prop("ro.boot.veritymode", verity_mode, sizeof(verity_mode));
    read_prop("ro.boot.warranty_bit", warranty_bit, sizeof(warranty_bit));
    read_prop("ro.boot.avb_version", avb_version, sizeof(avb_version));
    read_prop("ro.boot.vbmeta.device_state", vbmeta_state, sizeof(vbmeta_state));
    read_prop("sys.oem_unlock_allowed", oem_unlock, sizeof(oem_unlock));

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
        snprintf(details[n], 256, "vbmeta.device_state: %s", vbmeta_state[0] ? vbmeta_state : "(empty)");
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

    /* vbmeta.device_state=unlocked = DANGER */
    if (my_strstr(vbmeta_state, "unlocked") || my_strstr(vbmeta_state, "Unlocked")) {
        if (n < max_details) {
            snprintf(details[n], 256, "VBMeta device state unlocked");
            n++;
        }
        *out_status = 2;  /* DANGER */
        return n;
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

    /* yellow = WARNING (custom root of trust) */
    if (my_strstr(state, "yellow") || my_strstr(state, "Yellow")) {
        if (n < max_details) {
            snprintf(details[n], 256, "Custom root of trust (yellow state)");
            n++;
        }
        if (*out_status < 1) *out_status = 1;  /* WARNING */
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
    if (oem_unlock[0] == '1' && oem_unlock[1] == '\0') {
        if (n < max_details) {
            snprintf(details[n], 256, "OEM unlock allowed in developer options");
            n++;
        }
        if (*out_status < 1) *out_status = 1;  /* WARNING */
    }

    /* Cross-verify with /proc/cmdline to detect prop hook (Magisk modules may fake __system_property_get) */
    {
        char cmdline_buf[2048] = {0};
        int fd = my_open("/proc/cmdline", 0, 0);
        if (fd >= 0) {
            ssize_t rd = my_read(fd, cmdline_buf, sizeof(cmdline_buf) - 1);
            my_close(fd);
            if (rd > 0) {
                cmdline_buf[rd] = '\0';
                bool ok_state = verify_prop_vs_cmdline(state, "androidboot.verifiedbootstate", cmdline_buf, (size_t)rd);
                bool ok_flash = verify_prop_vs_cmdline(flash_locked, "androidboot.flash.locked", cmdline_buf, (size_t)rd);
                if (!ok_state || !ok_flash) {
                    if (n < max_details) {
                        snprintf(details[n], 256, "Prop vs cmdline mismatch (possible hook)");
                        n++;
                    }
                    if (*out_status < 1) *out_status = 1;  /* WARNING */
                }
            }
        }
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

/* memmem 替代：在 haystack 中查找 needle */
static const void *my_memmem(const void *haystack, size_t haylen, const void *needle, size_t needlen) {
    if (!haystack || !needle || needlen == 0 || needlen > haylen) return nullptr;
    const unsigned char *h = (const unsigned char *)haystack;
    const unsigned char *n = (const unsigned char *)needle;
    for (size_t i = 0; i <= haylen - needlen; i++) {
        if (my_memcmp(h + i, n, needlen) == 0) return h + i;
    }
    return nullptr;
}

/* Smaps 检测：可执行段中 Private_Dirty > 0 的可疑注入（正常代码段不应有 Private_Dirty） */
static int detect_private_dirty_in_smaps(char (*details)[256], int max_details) {
    int fd = my_open("/proc/self/smaps", 0, 0);  /* O_RDONLY */
    if (fd < 0) return 0;

    char line[512];
    bool in_executable = false;
    char current_mapping[384] = {0};
    int n = 0;
    size_t line_pos = 0;

    char buf[256];
    ssize_t rd;
    while ((rd = my_read(fd, buf, sizeof(buf))) > 0 && n < max_details) {
        for (ssize_t i = 0; i < rd && n < max_details; i++) {
            if (buf[i] == '\n' || line_pos >= sizeof(line) - 1) {
                line[line_pos] = '\0';
                line_pos = 0;
                /* 匹配内存映射行（权限包含 r-xp 或 r-x） */
                if (my_strstr(line, "r-xp") != nullptr || my_strstr(line, "r-x") != nullptr) {
                    in_executable = true;
                    my_strncpy(current_mapping, line, 383);
                    current_mapping[383] = '\0';
                }
                /* 在可执行段中查找 Private_Dirty */
                if (in_executable && my_strstr(line, "Private_Dirty:") != nullptr) {
                    int dirty_kb = 0;
                    sscanf(line, "Private_Dirty: %d kB", &dirty_kb);
                    if (dirty_kb > 0 && my_strstr(current_mapping, ".so") != nullptr) {
                        snprintf(details[n], 256, "Smaps: executable .so with Private_Dirty %d kB: %s",
                                 dirty_kb, current_mapping);
                        n++;
                    }
                    in_executable = false;
                }
            } else {
                line[line_pos++] = buf[i];
            }
        }
    }
    my_close(fd);
    return n;
}

/* VMap 检测：扫描 /proc/self/maps 中匿名可执行映射，搜索 Zygisk 特征字符串 */
static int scan_maps_for_zygisk_signatures(char (*details)[256], int max_details) {
    int fd = my_open("/proc/self/maps", 0, 0);
    if (fd < 0) return 0;

    char line[512];
    int n = 0;
    size_t line_pos = 0;

    char buf[256];
    ssize_t rd;
    while ((rd = my_read(fd, buf, sizeof(buf))) > 0 && n < max_details) {
        for (ssize_t i = 0; i < rd && n < max_details; i++) {
            if (buf[i] == '\n' || line_pos >= sizeof(line) - 1) {
                line[line_pos] = '\0';
                line_pos = 0;
                /* 查找 r-x 且 anon 的映射 */
                if (my_strstr(line, "r-x") != nullptr && my_strstr(line, "anon") != nullptr) {
                    unsigned long start = 0, end = 0;
                    sscanf(line, "%lx-%lx", &start, &end);
                    size_t size = end - start;
                    if (size >= 64 && size <= 64 * 1024 * 1024) {  /* 64B ~ 64MB 合理范围 */
                        for (int sig = 0; ZYGISK_SIGNATURES[sig] != nullptr && n < max_details; sig++) {
                            size_t sig_len = my_strlen(ZYGISK_SIGNATURES[sig]);
                            if (my_memmem((void *)start, size, ZYGISK_SIGNATURES[sig], sig_len) != nullptr) {
                                snprintf(details[n], 256, "VMap: Zygisk signature '%s' in anon exec: %s",
                                         ZYGISK_SIGNATURES[sig], line);
                                n++;
                                break;
                            }
                        }
                    }
                }
            } else {
                line[line_pos++] = buf[i];
            }
        }
    }
    my_close(fd);
    return n;
}

int env_detect_zygisk_injection(char (*details)[256], int max_details) {
    int n = 0;
    n = detect_private_dirty_in_smaps(details, max_details);
    if (n < max_details) {
        int vmap_n = scan_maps_for_zygisk_signatures(details + n, max_details - n);
        n += vmap_n;
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

/* Check if APK (ZIP) contains assets/xposed_init using syscall - bypasses hooked metaData */
static bool apk_has_xposed_init(const char *apk_path) {
    int fd = my_open(apk_path, 0, 0);  /* O_RDONLY */
    if (fd < 0) return false;

    /* Read in chunks; overlap to handle headers split across boundaries */
    char buf[4096];
    char overlap[64];
    size_t overlap_len = 0;
    ssize_t total = 0;
    const size_t max_scan = 4 * 1024 * 1024;  /* limit scan to 4MB (assets usually early) */
    bool found = false;

    while (total < max_scan) {
        ssize_t rd = my_read(fd, buf + overlap_len, sizeof(buf) - overlap_len);
        if (rd <= 0) break;
        rd += (ssize_t)overlap_len;
        overlap_len = 0;

        for (size_t i = 0; i + ZIP_HEADER_FIXED + 18 <= (size_t)rd; i++) {
            if (*(unsigned int *)(buf + i) != ZIP_LOCAL_SIG) continue;

            unsigned short fn_len = (unsigned char)buf[i + 26] | ((unsigned char)buf[i + 27] << 8);
            if (fn_len != 18 || i + ZIP_HEADER_FIXED + fn_len > (size_t)rd) continue;

            if (my_strncmp(buf + i + ZIP_HEADER_FIXED, "assets/xposed_init", 18) == 0) {
                found = true;
                break;
            }
        }
        if (found) break;
        /* Keep last 50 bytes for overlap (max header + short filename) */
        if ((size_t)rd > 50) {
            my_memcpy(overlap, buf + rd - 50, 50);
            overlap_len = 50;
        }
        total += rd;
    }
    my_close(fd);
    return found;
}

/* Check if pkg (len chars) already in out_pkgs[0..n-1] */
static bool pkg_in_list_by_name(char (*out_pkgs)[256], int n, const char *pkg, size_t len) {
    for (int i = 0; i < n; i++) {
        if (my_strlen(out_pkgs[i]) == len && my_strncmp(out_pkgs[i], pkg, len) == 0) return true;
    }
    return false;
}

/* Read Xposed modules.list (enabled modules), extract package names from APK paths. Needs root. */
static int read_modules_list(char (*out_pkgs)[256], int max_out) {
    static const char *PATHS[] = {
        "/data/data/de.robv.android.xposed.installer/conf/modules.list",
        "/data/adb/lspd/config/modules.list"
    };
    int n = 0;
    for (unsigned idx = 0; idx < sizeof(PATHS)/sizeof(PATHS[0]) && n < max_out; idx++) {
        int fd = my_open(PATHS[idx], 0, 0);  /* O_RDONLY */
        if (fd < 0) continue;

        char buf[2048];
        ssize_t rd = my_read(fd, buf, sizeof(buf) - 1);
        my_close(fd);
        if (rd <= 0) continue;
        buf[rd] = '\0';

        const char *p = buf;
        while (*p && n < max_out) {
            const char *line_end = p;
            while (*line_end && *line_end != '\n' && *line_end != '\r') line_end++;
            if (line_end > p) {
                /* Extract package from path: .../com.example.module-xxx/base.apk */
                const char *last_slash = nullptr;
                for (const char *q = p; q < line_end; q++) if (*q == '/') last_slash = q;
                if (last_slash && last_slash + 1 < line_end) {
                    const char *start = last_slash + 1;
                    const char *dash = my_strstr(start, "-");
                    size_t len = dash ? (size_t)(dash - start) : (size_t)(line_end - start);
                    if (len > 0 && len < 200 && !pkg_in_list_by_name(out_pkgs, n, start, len)) {
                        my_strncpy(out_pkgs[n], start, dash ? len : 199);
                        out_pkgs[n][dash ? len : 199] = '\0';
                        n++;
                    }
                }
            }
            p = line_end;
            while (*p == '\n' || *p == '\r') p++;
        }
    }
    return n;
}

/* Check if pkg (null-terminated) already in out_pkgs[0..n-1] */
static bool pkg_in_list(const char *pkg, char (*out_pkgs)[256], int n) {
    for (int i = 0; i < n; i++) {
        if (my_strcmp(out_pkgs[i], pkg) == 0) return true;
    }
    return false;
}

int env_verify_xposed_modules(const char **apk_paths, const char **pkg_names, int count,
                              char (*out_pkgs)[256], int max_out) {
    int n = 0;

    /* 1. Verify each APK has assets/xposed_init (syscall, bypasses metaData hook) */
    for (int i = 0; i < count && n < max_out; i++) {
        if (!apk_paths[i] || !pkg_names[i]) continue;
        if (apk_has_xposed_init(apk_paths[i]) && !pkg_in_list(pkg_names[i], out_pkgs, n)) {
            my_strncpy(out_pkgs[n], pkg_names[i], 255);
            out_pkgs[n][255] = '\0';
            n++;
        }
    }

    /* 2. Read modules.list (if root) - enabled modules from Xposed/LSPosed installer */
    int mod_count = read_modules_list(out_pkgs + n, max_out - n);
    for (int i = n; i < n + mod_count; i++) {
        if (pkg_in_list(out_pkgs[i], out_pkgs, n)) {
            /* duplicate, shift down */
            for (int j = i; j < n + mod_count - 1; j++)
                my_strncpy(out_pkgs[j], out_pkgs[j + 1], 255);
            mod_count--;
            i--;
        }
    }
    n += mod_count;
    return n;
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
