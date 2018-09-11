#ifndef ACK_H
#define ACK_H
#include <signal.h>
#include "slidingwindow.h"

void create_ack_timer(SlidingWindowElem*);
void unset_ack_timeout(SlidingWindowElem*);
void set_ack_timeout(SlidingWindowElem*, uint64_t);
void ack_timeout(union sigval);
void set_ack_flag(uint64_t, SlidingWindow*);

#endif
