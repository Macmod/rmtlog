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
    uint64_t *param;

    bool acked;
} SlidingWindowElem;

typedef struct SlidingWindow {
    struct SlidingWindowElem *window;

    pthread_mutex_t lock;
    uint64_t count;
    uint64_t width;
} SlidingWindow;

extern struct sockaddr_in server_addr;
extern SlidingWindow* sw;

SlidingWindow *make_sliding_window(uint64_t);
void sliding_window_insert(Message*);
bool get_elem(uint64_t, SlidingWindowElem**);
void set_ack_flag(uint64_t);
void block_until_ack();

#endif
