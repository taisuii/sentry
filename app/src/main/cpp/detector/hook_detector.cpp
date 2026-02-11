#include "hook_detector.h"
#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#define LOG_TAG "AntiFrida"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// Check for inline hooks by verifying function prologue
static bool check_function_hooked(void *func_addr) {
    if (func_addr == nullptr) {
        return false;
    }

    unsigned char *bytes = (unsigned char *)func_addr;

    // Check for ARM/ARM64 hook patterns
    // Common hook prologues:
    // - Branch to hook (B/BX/BL)
    // - LDR PC, [PC, #offset]
    // - MOV PC, Rm

    // Check for ARM64 branch
    if (bytes[0] == 0x00 || bytes[0] == 0x01 || bytes[0] == 0x02 || bytes[0] == 0x03) {
        // Potential branch instruction
        if ((bytes[3] & 0xFC) == 0x14) {
            LOGD("Potential inline hook detected (ARM64 branch)");
            return true;
        }
    }

    // Check for ARM32 hook patterns
    if (bytes[0] == 0x00 && bytes[1] == 0x00 && bytes[2] == 0x00 && bytes[3] == 0xEA) {
        // B (unconditional branch)
        LOGD("Potential inline hook detected (ARM32 branch)");
        return true;
    }

    // Check for LDR PC pattern
    if (bytes[3] == 0xE5 && bytes[2] == 0x9F && bytes[1] == 0xF0) {
        LOGD("Potential inline hook detected (LDR PC)");
        return true;
    }

    return false;
}

bool check_inline_hooks(void) {
    bool hooked = false;

    // Check common hooked functions
    void *malloc_addr = dlsym(RTLD_DEFAULT, "malloc");
    void *free_addr = dlsym(RTLD_DEFAULT, "free");
    void *open_addr = dlsym(RTLD_DEFAULT, "open");
    void *read_addr = dlsym(RTLD_DEFAULT, "read");
    void *write_addr = dlsym(RTLD_DEFAULT, "write");
    void *connect_addr = dlsym(RTLD_DEFAULT, "connect");
    void *socket_addr = dlsym(RTLD_DEFAULT, "socket");

    if (check_function_hooked(malloc_addr)) {
        LOGD("malloc appears to be hooked");
        hooked = true;
    }
    if (check_function_hooked(free_addr)) {
        LOGD("free appears to be hooked");
        hooked = true;
    }
    if (check_function_hooked(open_addr)) {
        LOGD("open appears to be hooked");
        hooked = true;
    }
    if (check_function_hooked(read_addr)) {
        LOGD("read appears to be hooked");
        hooked = true;
    }
    if (check_function_hooked(write_addr)) {
        LOGD("write appears to be hooked");
        hooked = true;
    }
    if (check_function_hooked(connect_addr)) {
        LOGD("connect appears to be hooked");
        hooked = true;
    }
    if (check_function_hooked(socket_addr)) {
        LOGD("socket appears to be hooked");
        hooked = true;
    }

    return hooked;
}

bool check_plt_hooks(void) {
    // Check PLT/GOT for suspicious entries
    // This requires parsing ELF headers which is complex
    // For now, we'll use a simplified check

    Dl_info info;
    void *malloc_addr = dlsym(RTLD_DEFAULT, "malloc");

    if (malloc_addr && dladdr(malloc_addr, &info)) {
        LOGD("malloc found in: %s", info.dli_fname ? info.dli_fname : "unknown");

        // If malloc is not in libc, it might be hooked
        if (info.dli_fname && strstr(info.dli_fname, "libc.so") == nullptr &&
            strstr(info.dli_fname, "libc++.so") == nullptr) {
            LOGD("malloc not in libc - possible PLT hook");
            return true;
        }
    }

    return false;
}

bool check_library_integrity(void) {
    // Check if critical libraries have been tampered with
    // This involves comparing memory sections with on-disk files

    // For now, just check if libc can be opened normally
    int fd = open("/system/lib64/libc.so", O_RDONLY);
    if (fd < 0) {
        fd = open("/system/lib/libc.so", O_RDONLY);
    }

    if (fd < 0) {
        LOGD("Cannot open libc - possible tampering");
        return true;
    }

    close(fd);
    return false;
}

bool detect_hooks(void) {
    bool hooked = false;

    if (check_inline_hooks()) {
        hooked = true;
    }

    if (check_plt_hooks()) {
        hooked = true;
    }

    if (check_library_integrity()) {
        hooked = true;
    }

    return hooked;
}
