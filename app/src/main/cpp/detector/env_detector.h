#ifndef ENV_DETECTOR_H
#define ENV_DETECTOR_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Magisk-specific detection - returns count, DANGER when > 0
int env_detect_magisk(char (*details)[256], int max_details);

// Bootloader state - out_status: 0=NORMAL,1=WARNING,2=DANGER; returns detail count
int env_detect_bootloader(int *out_status, char (*details)[256], int max_details);

// Suspicious files (Frida, adb paths) - returns count; no debug_ramdisk
int env_detect_suspicious_files(char (*details)[256], int max_details);

// LSPosed paths - returns count, DANGER when > 0
int env_detect_lsposed(char (*details)[256], int max_details);

// Read /proc/version for fingerprint (caller must free returned string)
char *env_read_proc_version(void);

// Emulator file check (caller provides build props for string matching)
int env_detect_emulator_files(const char *hardware, const char *product,
                              const char *device, const char *brand,
                              char (*details)[256], int max_details);

// Check if a port is open on 127.0.0.1 (for ADB 5555 etc.), uses syscall
bool env_check_port_open(int port);

// Container/cgroup check - returns count, DANGER when > 0
int env_detect_cgroup(char (*details)[256], int max_details);

// Netlink permission: normal app should get EACCES; if socket+bind succeed → DANGER (out_status 2)
int env_detect_netlink_permission(int *out_status, char (*details)[256], int max_details);

#ifdef __cplusplus
}
#endif

#endif /* ENV_DETECTOR_H */
