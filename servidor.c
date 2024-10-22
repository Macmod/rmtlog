#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "utils.h"
#include "message.h"
#include "serversw.h"
#include "clientlist.h"
#define ADDR_INTERNET false
#define INADDR (ADDR_INTERNET ? "192.168.0.66" : "127.0.0.1")

// Client list
ClientList clist;
pthread_mutex_t clistlock;

// Main vars
int sockfd;
uint16_t port;
double perr;

// Handle client message
void message_handler(FILE *fout, Message m, Client *client) {
    // Ack placeholder
    AckMessage am;

    // Client sliding window
    SlidingWindow *sw = client->sw;
    uint64_t nfe = sw->first->msg.seqnum;
    uint64_t lfa = sw->last->msg.seqnum;

    if (m.seqnum < nfe) {
#if DEBUG
        printf("--- Old frame [%lu < %lu] received. Acknowledging again.\n", m.seqnum, nfe);
#endif
    } else if (m.seqnum > lfa) {
#if DEBUG
        printf("--- Frame out of window [> %lu]. Discarding.\n", lfa);
#endif
        return;
    } else {
#if DEBUG
        printf("--- Inserting to window and acknowledging.\n");
#endif
        sliding_window_insert(sw, m);

        // Write all okay messages in left of window to file and slide
        while (sw->first->msg.buf != NULL) {
#if !DEBUG
            fwrite(sw->first->msg.buf, sizeof(char), sw->first->msg.sz, stdout);
            fwrite("\n", sizeof(char), 1, stdout);
#endif

            fwrite(sw->first->msg.buf, sizeof(char), sw->first->msg.sz, fout);
            fwrite("\n", sizeof(char), 1, fout);
            sliding_window_slide(sw);

#if DEBUG
            printf("--- Slid window to [%lu, %lu]\n",
                   sw->first->msg.seqnum,
                   sw->first->msg.seqnum + sw->width);
#endif
        }
    }

    // Fill ack
    fill_ack(&am, m.seqnum);

    // Reply ack
    send_ack(&am, sockfd, &client->addr_id, perr);

    pthread_mutex_unlock(&clistlock);
}

int main(int argc, char *argv[]) {
    // Disable buffering in stdout
    setvbuf(stdout, NULL, _IONBF, 0);

    // Seed PRNG poorly with time(NULL)
    srand(time(NULL));

    // Help
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <file> <port> <wrx> <perror>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Parse args
    FILE *fout = fopen(argv[1], "w");

    if (!fout) {
        fprintf(stderr, "Could not open output file '%s'.\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    // Disable buffering in output file
    setbuf(fout, NULL);

    if (!safe_read_uint16(argv[2], &port)) {
        fprintf(stderr, "The provided port '%s' is invalid.\n", argv[2]);
        exit(EXIT_FAILURE);
    }

    uint64_t wrx;
    if (!safe_read_uint64(argv[3], &wrx)) {
        fprintf(stderr, "Invalid wrx.\n");
        exit(EXIT_FAILURE);
    }

    if (!safe_read_double(argv[4], &perr)) {
        fprintf(stderr, "Invalid perr.\n");
        exit(EXIT_FAILURE);
    }

    // Setup listener address
    struct in_addr server_ip;
    inet_pton(AF_INET, INADDR, &server_ip);

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_addr = server_ip,
        .sin_port = htons(port)
    };

    // Setup listener
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1)
        logerr("Socket error");

    // Bind address/port
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
        logerr("Bind error");

    // Client address placeholder
    struct sockaddr_in addr;

    // Client pointer placeholder
    Client *client;

    // Setup client list
    pthread_mutex_init(&clistlock, NULL);
    clist = make_client_list();

    // Message placeholder
    char m_buf[MAXLN];
    Message m;

    // Put buffer on the stack
    // since we only need to keep one message per log line.
    m.buf = m_buf;

    // Handle messages from clients
    while (1) {
        // Receive message
        bool md5 = recv_message(&m, sockfd, &addr);
#if DEBUG
        printf("--- %s:%u\n", inet_ntoa(addr.sin_addr), addr.sin_port);
#endif

        pthread_mutex_lock(&clistlock);

        // Handle client
        if (!find_client(&clist, addr, &client)) {
#if DEBUG
            printf("--- New client\n");
#endif
            client = insert_client(&clist, addr, wrx);
        } else {
#if DEBUG
            printf("--- Existing client\n");
#endif
        }

        // Reset timeout
        set_client_timeout(client);

        if (md5) {
#if DEBUG
            printf("--- MD5: OK\n");
#endif

            message_handler(fout, m, client);
        } else {
#if DEBUG
            printf("--- MD5: CORRUPT\n");
#endif
        }

        pthread_mutex_unlock(&clistlock);
    }

    return 0;
}
