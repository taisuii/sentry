#include "port_scanner.h"
#include "../utils/syscall_utils.h"
#include <android/log.h>

#define LOG_TAG "AntiFrida"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// Avoid libc: use raw constants and minimal struct for syscall args
#define AF_INET      2
#define SOCK_STREAM  1
#define IPPROTO_TCP  6
#define SOL_SOCKET   1
#define SO_RCVTIMEO  20
#define SO_SNDTIMEO  21
#define O_RDONLY     0

#define CONNECT_TIMEOUT_SEC 2

// Minimal sockaddr_in layout for kernel (network byte order)
struct sockaddr_in_min {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int   sin_addr;
    unsigned char  pad[8];
};

static inline unsigned short host_to_net_short(unsigned short v) {
    return (unsigned short)((v >> 8) | (v << 8));
}

// 将 pid 转为十进制字符串写入 buf，避免使用 libc sprintf
static void pid_to_str(int pid, char *buf, size_t buf_len) {
    if (buf_len < 2) return;
    if (pid <= 0) {
        buf[0] = '0';
        buf[1] = '\0';
        return;
    }
    char tmp[16];
    int i = 0;
    unsigned int u = (unsigned int)pid;
    while (u && i < 15) {
        tmp[i++] = (char)('0' + (u % 10));
        u /= 10;
    }
    size_t j = 0;
    while (i > 0 && j < buf_len - 1) {
        buf[j++] = tmp[--i];
    }
    buf[j] = '\0';
}

// 检测是否存在进程名包含 "frida-server" 且该进程在 net/tcp 中有 LISTEN(0A)
// 用于覆盖 Frida 16+ 使用随机端口 (-l 0.0.0.0:0) 的情况
static bool detect_frida_server_listening(void) {
    char path[64];
    char comm[32];
    char tcp_buf[2048];
    const char prefix_proc[] = "/proc/";
    const char suffix_comm[] = "/comm";
    const char suffix_net_tcp[] = "/net/tcp";
    const char needle[] = "frida-server";
    const char listen_state[] = " 0A ";  // TCP LISTEN in /proc/net/tcp

    for (int pid = 1; pid < 32768 && pid > 0; pid++) {
        my_memset(path, 0, sizeof(path));
        my_strcpy(path, prefix_proc);
        pid_to_str(pid, path + sizeof(prefix_proc) - 1, sizeof(path) - (sizeof(prefix_proc) - 1));
        size_t plen = my_strlen(path);
        if (plen + sizeof(suffix_comm) >= sizeof(path)) continue;
        my_strcpy(path + plen, suffix_comm);

        int fd = my_open(path, O_RDONLY, 0);
        if (fd < 0) continue;

        my_memset(comm, 0, sizeof(comm));
        ssize_t n = my_read(fd, comm, sizeof(comm) - 1);
        my_close(fd);
        if (n <= 0) continue;

        comm[n] = '\0';
        while (n > 0 && (comm[n - 1] == '\n' || comm[n - 1] == '\r')) {
            comm[--n] = '\0';
        }
        if (my_strstr(comm, needle) == nullptr) continue;

        path[plen] = '\0';
        if (plen + sizeof(suffix_net_tcp) >= sizeof(path)) continue;
        my_strcpy(path + plen, suffix_net_tcp);

        fd = my_open(path, O_RDONLY, 0);
        if (fd < 0) continue;

        n = my_read(fd, tcp_buf, sizeof(tcp_buf) - 1);
        my_close(fd);
        if (n <= 0) continue;

        tcp_buf[n] = '\0';
        if (my_strstr(tcp_buf, listen_state) != nullptr) {
            LOGD("frida-server process (pid=%d) has LISTEN socket", pid);
            return true;
        }
    }
    return false;
}

// Frida 经典默认端口（不含 5000/8080 等通用端口，误报率高；Frida 16+ 支持随机端口，另靠 frida-server 进程名 + net/tcp 检测）
static const int FRIDA_PORTS[] = {
    27042, 27043, 27044, 0
};

// Last scan result for JNI to build DetectionResult (title/summary/details)
#define MAX_OPEN_PORTS 8
static int s_open_ports[MAX_OPEN_PORTS];
static int s_open_port_count = 0;

bool is_port_open(int port) {
    int sock = my_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return false;

    struct timeval_min {
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
    addr.sin_addr   = 0x0100007f; /* 127.0.0.1 in network byte order */

    int result = my_connect(sock, &addr, (unsigned int)sizeof(addr));
    my_close(sock);
    return (result == 0);
}

bool detect_frida_ports(void) {
    s_open_port_count = 0;
    bool found = false;

    for (int i = 0; FRIDA_PORTS[i] != 0 && s_open_port_count < MAX_OPEN_PORTS; i++) {
        if (is_port_open(FRIDA_PORTS[i])) {
            LOGD("Suspicious port detected: %d", FRIDA_PORTS[i]);
            s_open_ports[s_open_port_count++] = FRIDA_PORTS[i];
            found = true;
        }
    }

    /* 本进程 net/tcp 中的 Frida 经典端口十六进制码（27042=0x699A, 27043=0x699B, 27044=0x699C）*/
    int fd = my_open("/proc/self/net/tcp", O_RDONLY, 0);
    if (fd >= 0) {
        char buffer[4096];
        ssize_t n = my_read(fd, buffer, sizeof(buffer) - 1);
        my_close(fd);
        if (n > 0) {
            buffer[n] = '\0';
            if (my_strstr(buffer, "699A") || my_strstr(buffer, "699B") || my_strstr(buffer, "699C")) {
                LOGD("Frida port pattern in /proc/net/tcp");
                found = true;
                if (s_open_port_count < MAX_OPEN_PORTS) {
                    int p = 27042;
                    int j;
                    for (j = 0; j < s_open_port_count; j++) if (s_open_ports[j] == p) break;
                    if (j >= s_open_port_count) s_open_ports[s_open_port_count++] = p;
                }
            }
        }
    }

    /* Frida 16+ 随机端口：检测是否有进程名包含 frida-server 且该进程有 TCP LISTEN */
    if (s_open_port_count < MAX_OPEN_PORTS && detect_frida_server_listening()) {
        found = true;
        s_open_ports[s_open_port_count++] = 0;  /* 0 表示「frida-server 进程 + 监听」，非端口号 */
    }
    return found;
}

int get_frida_port_open_count(void) {
    return s_open_port_count;
}

int get_frida_port_open_at(int index) {
    if (index < 0 || index >= s_open_port_count) return -1;
    return s_open_ports[index];
}
