#ifndef CLIENTSW_H
#define CLIENTSW_H
#include <stdint.h>
#include <pthread.h>
#include "message.h"

// Sliding Window
typedef struct SlidingWindowElem {
    Message msg;

    // Timer variables
    timer_t timer;
    pthread_mutex_t tlock;

    bool acked;
    struct SlidingWindowElem *next;
} SlidingWindowElem;

typedef struct SlidingWindow {
    struct SlidingWindowElem *first;
    struct SlidingWindowElem *last;
    pthread_mutex_t lock;
    uint64_t count;
    uint64_t width;
} SlidingWindow;

SlidingWindow *make_sliding_window(uint64_t);
void sliding_window_insert(SlidingWindow*, Message*);
void set_ack_flag(uint64_t, SlidingWindow*);

#endif
