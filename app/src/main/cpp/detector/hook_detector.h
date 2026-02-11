#ifndef HOOK_DETECTOR_H
#define HOOK_DETECTOR_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool detect_hooks(void);
bool check_plt_hooks(void);
bool check_inline_hooks(void);
bool check_library_integrity(void);

#ifdef __cplusplus
}
#endif

#endif // HOOK_DETECTOR_H
