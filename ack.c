#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include "utils.h"
#include "ack.h"

int sockfd;
struct sockaddr_in server_addr;
uint64_t tout;
double perr;

// Create ack timer
void create_ack_timer(SlidingWindowElem *swe) {
    int status;
    struct sigevent se;
    timer_t timer_id;

    uint64_t *seqnum = malloc(sizeof(uint64_t));
    *seqnum = swe->msg.seqnum;

    // Setup parameters to be sent to ack timeout handler
    se.sigev_notify = SIGEV_THREAD;
    se.sigev_value.sival_ptr = (void*)seqnum;
    se.sigev_notify_function = ack_timeout;
    se.sigev_notify_attributes = NULL;

    status = timer_create(CLOCK_REALTIME, &se, &timer_id);
    if (status == -1)
        logerr("Timer creation error");

    swe->timer = timer_id;
    swe->param = seqnum;
}

// Setup ack reception timeout
void set_ack_timeout(SlidingWindowElem *swe, uint64_t tout) {
    if (swe->timer == NULL) {
#if DEBUG
        printf("--- Could not set timer. Timer already deleted.\n");
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
        printf("--- Could not unset timer. Timer already unset.\n");
#endif
        return;
    }

    timer_delete(swe->timer);
    swe->timer = NULL;
}

void ack_timeout(union sigval arg) {
    pthread_mutex_lock(&sw->lock);

    uint64_t *seqnum = (uint64_t*)arg.sival_ptr;
    SlidingWindowElem *swe;
    if (!get_elem(*seqnum, &swe)) {
#if DEBUG
        printf("[x] Ack %lu arrived just before timeout! Aborting...\n", *seqnum);
#endif
        pthread_mutex_unlock(&sw->lock);
        return;
    }

#if DEBUG
    printf("[!] Ack %lu timed out! Retransmitting...\n", *seqnum);
#endif

    Message *msg = &swe->msg;

    pthread_mutex_lock(&swe->tlock);
    send_message(msg, sockfd, &server_addr, perr);
    set_ack_timeout(swe, tout);
    pthread_mutex_unlock(&swe->tlock);

    pthread_mutex_unlock(&sw->lock);
}
