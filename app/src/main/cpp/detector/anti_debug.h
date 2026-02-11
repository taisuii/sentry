#ifndef ANTI_DEBUG_H
#define ANTI_DEBUG_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool detect_debug_mode(void);
bool check_tracer_pid(void);
bool check_debug_flag(void);
bool check_process_status(void);
int anti_debug_init(void);

#ifdef __cplusplus
}
#endif

#endif // ANTI_DEBUG_H
