#ifndef MEMORY_SCANNER_H
#define MEMORY_SCANNER_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool detect_frida_memory_signatures(void);
bool scan_maps_for_frida(void);

#ifdef __cplusplus
}
#endif

#endif // MEMORY_SCANNER_H
