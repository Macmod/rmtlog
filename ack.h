#ifndef ACK_H
#define ACK_H
#include <signal.h>
#include <stdint.h>
#include "clientsw.h"

extern int sockfd;
extern struct sockaddr_in server_addr;
extern uint64_t tout;
extern double perr;

void create_ack_timer(SlidingWindowElem*);
void unset_ack_timeout(SlidingWindowElem*);
void set_ack_timeout(SlidingWindowElem*, uint64_t);
void ack_timeout(union sigval);
void set_ack_flag(uint64_t, SlidingWindow*);

#endif
