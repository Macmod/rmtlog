#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "serversw.h"
#include "message.h"

SlidingWindow *make_sliding_window(uint64_t width) {
    SlidingWindow *sw = (SlidingWindow*)malloc(sizeof(SlidingWindow));
    sw->first = sw->last = NULL;
    sw->width = width;

    SlidingWindowElem *swe = NULL;
    Message void_msg = {0};

    for (uint64_t i = 0; i < width; i++) {
        void_msg.seqnum = i+1;

        swe = (SlidingWindowElem*)malloc(sizeof(SlidingWindowElem));
        swe->msg = void_msg;
        swe->next = NULL;

        if (i == 0)
            sw->first = swe;
        if (sw->last != NULL)
            sw->last->next = swe;
        sw->last = swe;
    }

    return sw;
}

void sliding_window_insert(SlidingWindow *sw, Message m) {
    SlidingWindowElem *aux = sw->first;

    while (aux != NULL) {
        if (m.seqnum == aux->msg.seqnum) {
            aux->msg.sz = m.sz;
            aux->msg.buf = (char*)malloc(sizeof(char)*m.sz);
            memcpy(aux->msg.buf, m.buf, m.sz);
            return;
        }

        aux = aux->next;
    }
}

void sliding_window_slide(SlidingWindow *sw) {
    Message void_msg = {0};
    SlidingWindowElem *aux, *swe;

    aux = sw->first->next;
    free_message(&sw->first->msg);
    free(sw->first);
    sw->first = aux;

    swe = (SlidingWindowElem*)malloc(sizeof(SlidingWindowElem));
    swe->msg = void_msg;
    swe->msg.seqnum = sw->last->msg.seqnum + 1;
    swe->next = NULL;

    sw->last->next = swe;
    sw->last = swe;
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
