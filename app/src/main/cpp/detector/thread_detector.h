#ifndef THREAD_DETECTOR_H
#define THREAD_DETECTOR_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool detect_frida_threads(void);

#ifdef __cplusplus
}
#endif

#endif // THREAD_DETECTOR_H
