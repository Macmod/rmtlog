#include <stdlib.h>
#include <stdio.h>
#include "slidingwindow.h"

SlidingWindow *make_sliding_window(uint64_t width) {
    SlidingWindow *sw = (SlidingWindow*)malloc(sizeof(SlidingWindow));
    sw->first = sw->last = (SlidingWindowElem*)malloc(sizeof(SlidingWindowElem));
    sw->count = 0;
    sw->width = width;

    return sw;
}

void sliding_window_insert(SlidingWindow *sw, Message m) {
    SlidingWindowElem *swe = (SlidingWindowElem*)malloc(sizeof(SlidingWindowElem));
    SlidingWindowElem *aux;

    swe->msg = m;
    swe->next = NULL;

    aux = sw->last;
    sw->last = aux->next = swe;

    if (sw->count == sw->width) {
        aux = sw->first;
        sw->first = aux->next;
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
            free(aux->msg.buf);
            free(aux);
            aux = ph;
        }
    }

    free(sw);
}
