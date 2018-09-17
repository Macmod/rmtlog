#ifndef SERVERSW_H
#define SERVERSW_H
#include <stdint.h>
#include "message.h"

// Sliding Window
typedef struct SlidingWindowElem {
    Message msg;
    struct SlidingWindowElem *next;
} SlidingWindowElem;

typedef struct SlidingWindow {
    struct SlidingWindowElem *first;
    struct SlidingWindowElem *last;
    uint64_t width;
} SlidingWindow;

SlidingWindow *make_sliding_window(uint64_t);
void sliding_window_insert(SlidingWindow*, Message);
void sliding_window_slide(SlidingWindow*);
void free_sliding_window(SlidingWindow*);

#endif
