#ifndef PORT_SCANNER_H
#define PORT_SCANNER_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool detect_frida_ports(void);
bool is_port_open(int port);

#ifdef __cplusplus
}
#endif

#endif // PORT_SCANNER_H
