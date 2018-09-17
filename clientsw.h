#ifndef CLIENTSW_H
#define CLIENTSW_H
#include <stdint.h>
#include "message.h"

// Sliding Window
typedef struct SlidingWindowElem {
    Message msg;
    timer_t timer;
    bool acked;
    struct AckTimeoutMsg *atm;
    struct SlidingWindowElem *next;
} SlidingWindowElem;

typedef struct SlidingWindow {
    struct SlidingWindowElem *first;
    struct SlidingWindowElem *last;
    uint64_t count;
    uint64_t width;
} SlidingWindow;

// Ack timeout message
typedef struct AckTimeoutMsg {
    int sockfd;
    SlidingWindowElem *swe;
    struct sockaddr_in *addr;
    uint64_t tout;
} AckTimeoutMsg;

SlidingWindow *make_sliding_window(uint64_t);
void sliding_window_insert(SlidingWindow*, Message*);
void free_sliding_window(SlidingWindow*);
void set_ack_flag(uint64_t, SlidingWindow*);

#endif
