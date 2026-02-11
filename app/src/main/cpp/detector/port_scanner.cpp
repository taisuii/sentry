#include "port_scanner.h"
#include <android/log.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define LOG_TAG "AntiFrida"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// Frida default ports
static const int FRIDA_PORTS[] = {
    27042,  // Default Frida server port
    27043,  // Alternative port
    27044,  // Alternative port
    5000,   // Some configurations
    8080,   // HTTP proxy
    0       // Terminator
};

bool is_port_open(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return false;
    }

    // Set non-blocking mode
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(port);

    int result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));

    close(sock);

    // If connect succeeds or returns EINPROGRESS, port might be open
    return (result == 0 || errno == EINPROGRESS || errno == ECONNREFUSED);
}

bool detect_frida_ports(void) {
    bool found_open_port = false;

    for (int i = 0; FRIDA_PORTS[i] != 0; i++) {
        if (is_port_open(FRIDA_PORTS[i])) {
            LOGD("Suspicious port detected: %d", FRIDA_PORTS[i]);
            found_open_port = true;
        }
    }

    // Also check for Frida in /proc/net/tcp
    int fd = open("/proc/self/net/tcp", O_RDONLY);
    if (fd >= 0) {
        char buffer[4096];
        ssize_t bytes = read(fd, buffer, sizeof(buffer) - 1);
        close(fd);

        if (bytes > 0) {
            buffer[bytes] = '\0';
            // Look for Frida's default port in hex (0x699A = 27042)
            if (strstr(buffer, "699A") != nullptr ||
                strstr(buffer, "699B") != nullptr ||
                strstr(buffer, "699C") != nullptr) {
                LOGD("Frida port pattern found in /proc/net/tcp");
                found_open_port = true;
            }
        }
    }

    return found_open_port;
}
