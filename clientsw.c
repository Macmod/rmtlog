#include <stdlib.h>
#include <stdio.h>
#include "clientsw.h"
#include "message.h"
#include "ack.h"

// Sliding Window
SlidingWindow *make_sliding_window(uint64_t width) {
    SlidingWindow *sw = (SlidingWindow*)malloc(sizeof(SlidingWindow));
    sw->first = sw->last = NULL;
    sw->count = 0;
    sw->width = width;

    return sw;
}

void sliding_window_insert(SlidingWindow *sw, Message m) {
    SlidingWindowElem *swe = (SlidingWindowElem*)malloc(sizeof(SlidingWindowElem));
    SlidingWindowElem *aux;

    swe->msg = m;
    swe->next = NULL;
    swe->acked = false;

    if (sw->first == NULL) {
        sw->first = sw->last = swe;
        return;
    }

    aux = sw->last;
    sw->last = aux->next = swe;

    if (sw->count == sw->width) {
        aux = sw->first;
        sw->first = aux->next;
        free_message(&aux->msg);
        free(aux);
    } else {
        sw->count++;
    }
}

void free_sliding_window(SlidingWindow *sw) {
    if (sw->first != NULL) {
        SlidingWindowElem *aux = sw->first,
                          *ph;
        while (aux != NULL) {
            ph = aux->next;
            free_message(&aux->msg);
            free(aux);
            aux = ph;
        }
    }

    free(sw);
}

// Set ack flag
void set_ack_flag(uint64_t seqnum, SlidingWindow *sw) {
    SlidingWindowElem *aux = sw->first;

    while (aux != NULL) {
        if (seqnum == aux->msg.seqnum) {
            unset_ack_timeout(aux);
            aux->acked = true;
            return;
        }

        aux = aux->next;
    }
}
