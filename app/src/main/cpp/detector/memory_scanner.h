#ifndef MEMORY_SCANNER_H
#define MEMORY_SCANNER_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool detect_frida_memory_signatures(void);
bool scan_maps_for_frida(void);

/** Fills details array with findings, returns count. Uses syscall to bypass libc hook. */
int get_memory_signature_details(char (*details)[256], int max_details);

#ifdef __cplusplus
}
#endif

#endif // MEMORY_SCANNER_H
