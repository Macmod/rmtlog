#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include "clientsw.h"
#include "message.h"
#include "ack.h"

SlidingWindow *sw;

// Sliding Window
SlidingWindow *make_sliding_window(uint64_t width) {
    SlidingWindow *sw = malloc(sizeof(SlidingWindow));
    SlidingWindowElem *window = malloc(sizeof(SlidingWindowElem)*width);

    sw->window = window;
    sw->count = 0;
    sw->width = width;
    pthread_mutex_init(&sw->lock, NULL);

    return sw;
}

void sliding_window_insert(Message *m) {
    pthread_mutex_lock(&sw->lock);

    if (sw->count != sw->width) {
        sw->count++;
    }

    sw->window[sw->count-1].msg = *m;
    sw->window[sw->count-1].acked = false;
    sw->window[sw->count-1].timer = NULL;
    pthread_mutex_init(&sw->window[sw->count-1].tlock, NULL);

    // Set ack timeout
    create_ack_timer(&sw->window[sw->count-1]);
    set_ack_timeout(&sw->window[sw->count-1], tout);

    pthread_mutex_unlock(&sw->lock);
}

bool get_elem(uint64_t seqnum, SlidingWindowElem **swe) {
    uint64_t fst = sw->window[0].msg.seqnum,
             lst = sw->window[sw->count-1].msg.seqnum;

    if (seqnum < fst || seqnum > lst) {
        return false;
    }

    *swe = &sw->window[seqnum - fst];
    return true;
}

// Set ack flag
void set_ack_flag(uint64_t seqnum) {
    SlidingWindowElem *aux;
    get_elem(seqnum, &aux);

    // Lock access to timer meanwhile
    pthread_mutex_lock(&aux->tlock);
    unset_ack_timeout(aux);
    aux->acked = true;
    pthread_mutex_unlock(&aux->tlock);
}

void block_until_ack() {
    AckMessage ack;

    while (!sw->window[0].acked) {
        if (recv_ack(&ack, sockfd, &server_addr)) {
#if DEBUG
            printf("--- MD5: OK\n");
#endif

            set_ack_flag(ack.seqnum);
        } else {
#if DEBUG
            printf("--- MD5: CORRUPT\n");
#endif
        }
    }

    // Slide (lock access to window meanwhile)
    pthread_mutex_lock(&sw->lock);
    free_message(&sw->window[0].msg);

    for (uint64_t i = 0; i < sw->count-1; i++) {
        sw->window[i] = sw->window[i+1];
    }
    pthread_mutex_unlock(&sw->lock);

#if DEBUG
    printf("[!] Window slid to [%lu, %lu]\n",
           sw->window[0].msg.seqnum, sw->window[0].msg.seqnum + sw->count - 1);
#endif
}
