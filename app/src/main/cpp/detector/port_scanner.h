#ifndef PORT_SCANNER_H
#define PORT_SCANNER_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool detect_frida_ports(void);
bool is_port_open(int port);
int get_frida_port_open_count(void);
int get_frida_port_open_at(int index);
int get_frida_process_detail_count(void);
const char *get_frida_process_detail_at(int index);

#ifdef __cplusplus
}
#endif

#endif // PORT_SCANNER_H
