#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "utils.h"
#include "clientlist.h"

// Create client timer
void create_client_timer(Client *client) {
    struct sigevent se;
    int status;
    timer_t timer_id;

    se.sigev_notify = SIGEV_THREAD;
    se.sigev_value.sival_ptr = (void*)client;
    se.sigev_notify_function = client_timeout;
    se.sigev_notify_attributes = NULL;

    status = timer_create(CLOCK_REALTIME, &se, &timer_id);
    if (status == -1)
        logerr("Timer creation error");

    client->timer = timer_id;
}

// Setup client deletion timeout
void set_client_timeout(Client *client) {
    int status;
    struct itimerspec ts;

    ts.it_value.tv_sec = CLIENT_TIMEOUT_SECS;
    ts.it_value.tv_nsec = CLIENT_TIMEOUT_USECS;
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;

    status = timer_settime(client->timer, 0, &ts, 0);
    if (status == -1)
        logerr("Timer arming error");
}

// Unset client deletion timeout
void unset_client_timeout(Client *client) {
    int status;
    struct itimerspec ts;

    ts.it_value.tv_sec = 0;
    ts.it_value.tv_nsec = 0;
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;

    status = timer_settime(client->timer, 0, &ts, 0);
    if (status == -1)
        logerr("Timer disarming error");
}

// Handle client timeout
void client_timeout(union sigval arg) {
    Client *c = arg.sival_ptr;

#ifdef DEBUG
    printf("Client %s:%u timed out!\n",
           inet_ntoa(c->addr_id.sin_addr), c->addr_id.sin_port);
#endif

    remove_client(&clist, c->addr_id);
}

// Create client list
ClientList make_client_list() {
    ClientList cl;
    cl.first = cl.last = NULL;
    cl.len = 0;

    return cl;
}

// Find client in list
bool find_client(ClientList *cl, struct sockaddr_in addr,
                   Client **c) {
    Client *aux = cl->first;
    while (aux != NULL) {
        if (addr_cmp(aux->addr_id, addr)) {
            *c = aux;
            return true;
        }

        aux = aux->next;
    }

    return false;
}

// Remove client from list
void remove_client(ClientList *cl, struct sockaddr_in addr) {
    Client *aux = cl->first,
           *prev = NULL;

    while (aux != NULL) {
        if (addr_cmp(aux->addr_id, addr)) {
            timer_delete(aux->timer);
            if (prev != NULL)
                prev->next = aux->next;
            free(aux);
            return;
        }

        prev = aux;
        aux = aux->next;
    }
}

// Insert client in list
Client *insert_client(ClientList *cl, struct sockaddr_in addr, uint64_t width) {
    Client *c = (Client*)malloc(sizeof(Client));
    c->addr_id = addr;
    c->timer = NULL;
    c->nfe = 0;
    c->width = width;

    c->next = NULL;
    if (cl->last == NULL) {
        cl->first = c;
    } else {
        cl->last->next = c;
    }

    cl->last = c;

    create_client_timer(c);
    set_client_timeout(c);
    return c;
}
