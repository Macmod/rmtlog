#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "utils.h"
#include "message.h"
#include "slidingwindow.h"
#define DEBUG true
#define INADDR "127.0.0.1"
#define MAX_PENDING_CONNS 10
#define CLIENT_TIMEOUT_SECS 5
#define CLIENT_TIMEOUT_USECS 0
#define MAXLINE 65536
#define addr_cmp(a,b) (((a).sin_addr.s_addr == (b).sin_addr.s_addr) && ((a).sin_port == (b).sin_port))

// Client list
typedef struct Client {
    struct sockaddr_in addr_id;

    uint64_t nfe;
    uint64_t width;
    struct Client *next;

    timer_t timer;
} Client;

typedef struct ClientList {
    struct Client *first;
    struct Client *last;
    uint16_t len;
} ClientList;

ClientList make_client_list() {
    ClientList cl;
    cl.first = cl.last = NULL;
    cl.len = 0;

    return cl;
}

// Client list
// (global since I implement inactive client
//  timeouts using threads)
ClientList clist;

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

void remove_client(ClientList *cl, struct sockaddr_in addr) {
    Client *aux = cl->first,
           *prev = NULL;

    while (aux != NULL) {
        if (addr_cmp(aux->addr_id, addr)) {
            if (prev != NULL)
                prev->next = aux->next;
            free(aux);
            return;
        }

        prev = aux;
        aux = aux->next;
    }
}

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
    return c;
}

// Client timeout
void client_timeout(union sigval arg) {
    Client *c = arg.sival_ptr;

#ifdef DEBUG
    printf("Client %s:%u timed out!\n",
           inet_ntoa(c->addr_id.sin_addr), c->addr_id.sin_port);
#endif

    remove_client(&clist, c->addr_id);
}

// Unset client deletion timeout
void unset_client_timeout(Client *client) {
    if (client->timer == NULL)
        return;

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

// Setup client deletion timeout
void set_client_timeout(Client *client) {
    timer_t timer_id;
    int status;
    struct itimerspec ts;
    struct sigevent se;

    se.sigev_notify = SIGEV_THREAD;
    se.sigev_value.sival_ptr = (void*)client;
    se.sigev_notify_function = client_timeout;
    se.sigev_notify_attributes = NULL;

    ts.it_value.tv_sec = CLIENT_TIMEOUT_SECS;
    ts.it_value.tv_nsec = CLIENT_TIMEOUT_USECS;
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;

    status = timer_create(CLOCK_REALTIME, &se, &timer_id);
    if (status == -1)
        logerr("Timer creation error");

    status = timer_settime(timer_id, 0, &ts, 0);
    if (status == -1)
        logerr("Timer arming error");

    client->timer = timer_id;
}

// Handle client message
void *message_handler(int sockfd, Message m, Client *client, FILE *fin) {
    // Unset client timeout
    unset_client_timeout(client);

    // Ack placeholder
    AckMessage am;

    // Write log
    fwrite(m.buf, 1, m.sz, fin);

    // Reply ack
    am = make_ack(m.seqnum);
    send_ack(&am, sockfd, &client->addr_id);

    // Set client timeout
    set_client_timeout(client);
}

int main(int argc, char *argv[]) {
    // Disable stdout buffering
    setvbuf(stdout, NULL, _IONBF, 0);

    // Help
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <file> <port> <wrx> <perror>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int sockfd;
    uint16_t port;
    struct in_addr server_addr;
    struct sockaddr_in client;

    // Parse args
    FILE *fin = fopen(argv[1], "a+");
    if (!fin) {
        fprintf(stderr, "Could not open output file '%s'.", argv[1]);
        exit(EXIT_FAILURE);
    }

    if (!safe_read_uint16(argv[2], &port)) {
        fprintf(stderr, "The provided port '%s' is invalid.\n", argv[2]);
        exit(EXIT_FAILURE);
    }

    uint64_t wrx;
    if (!safe_read_uint64(argv[3], &wrx)) {
        fprintf(stderr, "Invalid wrx.\n");
        exit(EXIT_FAILURE);
    }

    double perr;
    if (!safe_read_double(argv[4], &perr)) {
        fprintf(stderr, "Invalid perr.\n");
        exit(EXIT_FAILURE);
    }

    // Setup listener address
    inet_pton(AF_INET, INADDR, &server_addr);

    struct sockaddr_in server = {
        .sin_family = AF_INET,
        .sin_addr = server_addr,
        .sin_port = htons(port)
    };

    // Setup listener
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1)
        logerr("Socket error");

    // Bind address/port
    if (bind(sockfd, (struct sockaddr*)&server, sizeof(server)) < 0)
        logerr("Bind error");

    // Listen
    listen(sockfd, MAX_PENDING_CONNS);

    // Client address placeholder
    struct sockaddr_in addr;

    // Client pointer placeholder
    Client *cptr;

    // Setup client list
    clist = make_client_list();

    // Message placeholder
    Message m;

    // Spawn one handler thread for each client
    while (1) {
        // Receive message
        recv_message(&m, sockfd, &addr);

#if DEBUG
        printf("--- %s:%u (seqnum=%u, len=%u)\n", inet_ntoa(addr.sin_addr), addr.sin_port, m.seqnum, m.sz);
#endif
        if (!find_client(&clist, addr, &cptr)) {
#ifdef DEBUG
            printf("--- New client\n");
#endif
            cptr = insert_client(&clist, addr, wrx);
        } else {
            cptr->nfe++;
#ifdef DEBUG
            printf("--- Existing client\n");
#endif
        }

        if (m.seqnum < cptr->nfe || m.seqnum > cptr->nfe+cptr->width)
            continue;

        if (check_msg_md5(&m)) {
#ifdef DEBUG
            printf("--- MD5: OK\n");
#endif
            message_handler(sockfd, m, cptr, fin);
        } else {
#ifdef DEBUG
            printf("--- MD5: CORRUPT\n");
#endif
        }
    }

    return 0;
}
