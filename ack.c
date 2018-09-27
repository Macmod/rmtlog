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

    // Setup parameters to be sent to ack timeout handler
    se.sigev_notify = SIGEV_THREAD;
    se.sigev_value.sival_ptr = (void*)swe;
    se.sigev_notify_function = ack_timeout;
    se.sigev_notify_attributes = NULL;

    status = timer_create(CLOCK_REALTIME, &se, &timer_id);
    if (status == -1)
        logerr("Timer creation error");

    swe->timer = timer_id;
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

    pthread_mutex_lock(&swe->tlock);
    timer_delete(swe->timer);
    swe->timer = NULL;
    pthread_mutex_unlock(&swe->tlock);
}

void ack_timeout(union sigval arg) {
    SlidingWindowElem *swe = (SlidingWindowElem*)arg.sival_ptr;

    pthread_mutex_lock(&swe->tlock);
    Message *msg = &swe->msg;

#if DEBUG
    printf("[!] Ack for %lu timed out! Retransmitting...\n", msg->seqnum);
#endif
    if (swe->msg.buf == NULL) {
        printf("[!] Window slid right before retransmit for %lu! Aborting...\n", msg->seqnum);
        return;
    }

    send_message(msg, sockfd, &server_addr, perr);
    set_ack_timeout(swe, tout);

    pthread_mutex_unlock(&swe->tlock);
}
