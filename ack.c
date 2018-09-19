#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include "utils.h"
#include "ack.h"

// Create ack timer
void create_ack_timer(SlidingWindowElem *swe, int sockfd,
                      struct sockaddr_in *addr, uint64_t tout) {
    int status;
    struct sigevent se;
    timer_t timer_id;

    // Setup parameters to be sent to ack timeout handler
    AckTimeoutMsg *atm = malloc(sizeof(AckTimeoutMsg));
    atm->swe = swe;
    atm->sockfd = sockfd;
    atm->addr = addr;
    atm->tout = tout;

    se.sigev_notify = SIGEV_THREAD;
    se.sigev_value.sival_ptr = (void*)atm;
    se.sigev_notify_function = ack_timeout;
    se.sigev_notify_attributes = NULL;

    status = timer_create(CLOCK_REALTIME, &se, &timer_id);
    if (status == -1)
        logerr("Timer creation error");

    swe->atm = atm;
    swe->timer = timer_id;
}

// Setup ack reception timeout
void set_ack_timeout(SlidingWindowElem *swe, uint64_t tout) {
    if (swe->timer == NULL) {
#if DEBUG
        printf("--- Could not set timer. Timer already unset.\n");
#endif
        return;
    }

    int status;
    struct itimerspec ts;

    ts.it_value.tv_sec = tout;
    ts.it_value.tv_nsec = 0;
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;

    status = timer_settime(swe->timer, 0, &ts, 0);
    if (status == -1)
        logerr("Timer arming error");
}

// Unset ack reception timeout
void unset_ack_timeout(SlidingWindowElem *swe) {
    if (swe->timer == NULL) {
#if DEBUG
        printf("--- Could not unset timer. Timer already unset.");
#endif
        return;
    }

    free(swe->atm);
    timer_delete(swe->timer);
    swe->timer = NULL;
}

void ack_timeout(union sigval arg) {
    AckTimeoutMsg *atm = arg.sival_ptr;

    SlidingWindowElem *swe = atm->swe;
    int sockfd = atm->sockfd;
    uint64_t tout = atm->tout;
    struct sockaddr_in *addr = atm->addr;
    Message *msg = &swe->msg;

#if DEBUG
    printf("[!] Ack for %u timed out! Retransmitting...\n", msg->seqnum);
#endif

    send_message(msg, sockfd, addr);
    set_ack_timeout(swe, tout);
}
