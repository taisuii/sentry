#include "anti_debug.h"
#include <android/log.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define LOG_TAG "AntiFrida"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// Use syscall directly to bypass potential hooks
static inline long my_syscall(long number, ...) {
    register long r7 __asm__("r7") = number;
    register long r0 __asm__("r0");
    register long r1 __asm__("r1");
    register long r2 __asm__("r2");
    register long r3 __asm__("r3");

    __asm__ __volatile__(
        "swi 0"
        : "=r"(r0)
        : "r"(r7), "r"(r0), "r"(r1), "r"(r2), "r"(r3)
        : "memory"
    );

    return r0;
}

bool check_tracer_pid(void) {
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) {
        return false;
    }

    char buffer[4096];
    ssize_t bytes = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);

    if (bytes <= 0) {
        return false;
    }

    buffer[bytes] = '\0';

    // Look for TracerPid line
    char *tracer_line = strstr(buffer, "TracerPid:");
    if (tracer_line) {
        int tracer_pid = atoi(tracer_line + 10);
        if (tracer_pid != 0) {
            LOGD("Process is being traced by PID: %d", tracer_pid);
            return true;
        }
    }

    return false;
}

bool check_debug_flag(void) {
    // Check if debugger is connected via android_debuggable
    // This is a simplified check - in production, use proper APIs

    // Check if we can detect debugger through status
    int fd = open("/proc/self/stat", O_RDONLY);
    if (fd >= 0) {
        char buffer[256];
        ssize_t bytes = read(fd, buffer, sizeof(buffer) - 1);
        close(fd);

        if (bytes > 0) {
            buffer[bytes] = '\0';
            // Process state in /proc/pid/stat - 't' means tracing stop
            char *start = strchr(buffer, ')');
            if (start && *(start + 2) == 't') {
                LOGD("Process state indicates tracing");
                return true;
            }
        }
    }

    return false;
}

bool check_process_status(void) {
    // Check various process status indicators
    bool suspicious = false;

    // Check for suspicious environment variables
    char *debugger_env = getenv("DEBUGGER");
    if (debugger_env) {
        LOGD("DEBUGGER environment variable detected");
        suspicious = true;
    }

    char *ld_preload = getenv("LD_PRELOAD");
    if (ld_preload) {
        LOGD("LD_PRELOAD detected: %s", ld_preload);
        if (strstr(ld_preload, "frida") || strstr(ld_preload, "hook")) {
            suspicious = true;
        }
    }

    return suspicious;
}

bool detect_debug_mode(void) {
    bool debug_detected = false;

    if (check_tracer_pid()) {
        debug_detected = true;
    }

    if (check_debug_flag()) {
        debug_detected = true;
    }

    if (check_process_status()) {
        debug_detected = true;
    }

    return debug_detected;
}

// Attempt to set anti-ptrace protection
int anti_debug_init(void) {
    // Try to set ourselves as non-traceable
    // This uses the direct syscall to bypass any hooked ptrace

#ifdef __arm__
    // ARM32 syscall
    long result = my_syscall(__NR_ptrace, PTRACE_TRACEME, 0, 0, 0);
    if (result < 0) {
        LOGD("Already being traced or cannot set PTRACE_TRACEME");
        return -1;
    }
#elif __aarch64__
    // ARM64 uses different mechanism, simplified here
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
        LOGD("PTRACE_TRACEME failed - may already be traced");
        return -1;
    }
#else
    // Generic fallback
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
        LOGD("PTRACE_TRACEME failed - may already be traced");
        return -1;
    }
#endif

    return 0;
}
