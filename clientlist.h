#ifndef CLIENTLIST_H
#define CLIENTLIST_H
#include <stdint.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "serversw.h"
#include "utils.h"
#define CLIENT_TIMEOUT_SECS 30
#define CLIENT_TIMEOUT_USECS 0

// Client list
typedef struct Client {
    struct sockaddr_in addr_id;

    struct SlidingWindow *sw;
    struct Client *next;

    timer_t timer;
} Client;

typedef struct ClientList {
    struct Client *first;
    struct Client *last;
    uint16_t len;
} ClientList;

// Client list
// (global since I implement inactive client
//  timeouts using threads)
extern ClientList clist;

void init_client_lock();
void destroy_client_lock();
void create_client_timer(Client*);
void set_client_timeout(Client*);
void unset_client_timeout(Client*);
ClientList make_client_list();
bool find_client(ClientList*, struct sockaddr_in, Client**);
void remove_client(ClientList*, struct sockaddr_in);
Client *insert_client(ClientList*, struct sockaddr_in, uint64_t);
void client_timeout(union sigval);

#endif
