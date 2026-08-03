#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>

#ifdef NDEBUG

#define DEBUG_LOG(fmt, ...) ((void)0)

#else

#define DEBUG_LOG(fmt, ...)                    \
    fprintf(stderr,                            \
            "[DEBUG] %s:%d %s() -- " fmt "\n", \
            __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#endif /* NDEBUG */

#endif /* DEBUG_H */