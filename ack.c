#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include "utils.h"
#include "ack.h"

// Unset ack reception timeout
void unset_ack_timeout(SlidingWindowElem *swe) {
    if (swe->timer == NULL)
        return;

    int status;
    struct itimerspec ts;

    ts.it_value.tv_sec = 0;
    ts.it_value.tv_nsec = 0;
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;

    status = timer_settime(swe->timer, 0, &ts, 0);
    if (status == -1)
        logerr("Timer disarming error");

    printf("unset %u\n", swe->msg.seqnum);
    free(swe->atm);
    timer_delete(swe->timer);
}

// Setup ack reception timeout
void set_ack_timeout(SlidingWindowElem *swe, uint64_t tout) {
    AckTimeoutMsg *atm = malloc(sizeof(AckTimeoutMsg));

    timer_t timer_id;
    int status;
    struct itimerspec ts;
    struct sigevent se;

    se.sigev_notify = SIGEV_THREAD;
    se.sigev_value.sival_ptr = (void*)atm;
    se.sigev_notify_function = ack_timeout;
    se.sigev_notify_attributes = NULL;

    ts.it_value.tv_sec = tout;
    ts.it_value.tv_nsec = 0;
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;

    status = timer_create(CLOCK_REALTIME, &se, &timer_id);
    if (status == -1)
        logerr("Timer creation error");

    status = timer_settime(timer_id, 0, &ts, 0);
    if (status == -1)
        logerr("Timer arming error");

    swe->timer = timer_id;
    swe->atm = atm;
    printf("set %u\n", swe->msg.seqnum);
}

void ack_timeout(union sigval arg) {
    AckTimeoutMsg *atm = arg.sival_ptr;

    SlidingWindowElem *swe = atm->swe;
    int sockfd = atm->sockfd;
    uint64_t tout = atm->tout;
    struct sockaddr_in *addr = atm->addr;
    Message *msg = &swe->msg;

#ifdef DEBUG
    printf("[!] Ack for %u timed out! Retransmitting...\n", msg->seqnum);
#endif

    send_message(msg, sockfd, addr);
#ifdef DEBUG
    printf("[!] Retransmitted message (seqnum=%u, len=%u)\n", msg->seqnum, msg->sz);
#endif

    set_ack_timeout(swe, tout);
    free(atm);
}

// Set ack flag
void set_ack_flag(uint64_t seqnum, SlidingWindow *sw) {
    SlidingWindowElem *aux = sw->first;

    while (aux != NULL) {
        if (seqnum == aux->msg.seqnum) {
            aux->acked = true;
            unset_ack_timeout(aux);
            return;
        }

        aux = aux->next;
    }
}
