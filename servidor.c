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
#include "clientlist.h"
#define INADDR "127.0.0.1"
#define MAX_PENDING_CONNS 10

// Client list
ClientList clist;

// Handle client message
void *message_handler(int sockfd, Message m, Client *client, FILE *fin) {
    // Unset client timeout
    unset_client_timeout(client);

    // Ack placeholder
    AckMessage am;

    // Write log
    fwrite(m.buf, 1, m.sz, fin);

    // Reply ack
    fill_ack(&am, m.seqnum);
    send_ack(&am, sockfd, &client->addr_id);

    // Reset client timeout
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
    char m_buf[MAXLINE];
    Message m;

    // Put buffer on the stack
    // since we only need to keep one message per log line.
    m.buf = m_buf;

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
