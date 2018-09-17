#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include "utils.h"
#include "message.h"
#include "clientsw.h"
#include "ack.h"
#define MESSAGE_CORRUPTION true

int sockfd;
uint16_t port;
size_t nsent = 0;
FILE *fin;

// Execution log structure
typedef struct ExecutionLog {
    size_t nmsg;
    size_t nerror;
} ExecutionLog;

// Client handler
ExecutionLog client_handler(void *server_addr, uint64_t width,
                            uint64_t tout, double perr) {
    ExecutionLog xl;

    char buf[MAXLN];
    SlidingWindow *window = make_sliding_window(width);

    Message m;

    AckMessage ack;

    uint64_t seqnum = 1;

#if DEBUG
    printf("[!] Sending file...\n");
#endif
    while (fgets(buf, MAXLN, fin)) {
        // Print log line
#if !DEBUG
        printf("%s", buf);
#endif

        // Increment message count
        xl.nmsg += 1;

        // Allocate space for message
        alloc_message(&m, strlen(buf));

        // Fill message
        fill_message(&m, buf, seqnum);

#if MESSAGE_CORRUPTION
        // Corrupt some md5s
        if ((double)rand()/RAND_MAX < perr) {
#if DEBUG
            printf("--- Corruption happened to message.\n");
#endif
            m.md5[15] += 1;
            xl.nerror += 1;
        }
#endif

        // Put message into sliding window
        sliding_window_insert(window, &m);

        // Send message
        send_message(&m, sockfd, server_addr);

        // Set ack timeout
        create_ack_timer(window->last, sockfd, server_addr, tout);
        set_ack_timeout(window->last, tout);

        seqnum++;

        // Block until ack of first element when window full
        if (window->count == window->width) {
            while (!window->first->acked) {
#if DEBUG
                printf("[!] Window waiting for Ack with seqnum=%u\n",
                       window->first->msg.seqnum);
#endif
                if (recv_ack(&ack, sockfd, server_addr)) {
#if DEBUG
                    printf("--- MD5: OK\n");
#endif
                    set_ack_flag(ack.seqnum, window);
                } else {
#if DEBUG
                    printf("--- MD5: CORRUPT\n");
#endif
                }
            }
        }
    }

    // Receive acks for last window
    // (no more lines to read, although still need to close window)
    for (uint64_t i = 0; i < width+1; i++) {
        while (!window->first->acked) {
#if DEBUG
            printf("[!] Window waiting for Ack with seqnum=%u\n",
                   window->first->msg.seqnum);
#endif
            if (recv_ack(&ack, sockfd, server_addr)) {
#if DEBUG
                printf("--- MD5: OK\n");
#endif
                set_ack_flag(ack.seqnum, window);
            } else {
#if DEBUG
                printf("--- MD5: CORRUPT\n");
#endif
            }
        }

        // Free last elements from sliding window
        SlidingWindowElem *aux = window->first->next;

        free_message(&window->first->msg);
        free(window->first);

        window->first = aux;
    }

    // Free sliding window
    free(window);

    return xl;
}

int main(int argc, char *argv[]) {
    struct in_addr server_addr;
    struct sockaddr_in client;
    struct timespec start_time, end_time;
    double total_time;

    // Measure start time
    clock_gettime(CLOCK_REALTIME, &start_time);

    // Disable stdout buffering
    setvbuf(stdout, NULL, _IONBF, 0);

    // Seed PRNG poorly with time(NULL)
    srand(time(NULL));

    // Help
    if (argc < 6) {
        fprintf(stderr,
                "Usage: %s <file> <ip>:<port> <wtx> <tout> <perror>\n",
                argv[0]);
        exit(EXIT_FAILURE);
    }

    // Parse args
    fin = fopen(argv[1], "r");

    if (!fin) {
        fprintf(stderr, "Could not open input file '%s'.\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    // Disable buffering in output file
    setbuf(fin, NULL);

    char *ip_str = strtok(argv[2], ":");
    char *port_str = strtok(NULL, ":");

    // Setup target address
    inet_pton(AF_INET, ip_str, &server_addr);

    // Setup port
    if (!safe_read_uint16(port_str, &port)) {
        fprintf(stderr, "The provided port '%s' is invalid.\n", argv[2]);
        exit(EXIT_FAILURE);
    }

    // Setup wtx, tout & perr
    uint64_t wtx;
    if (!safe_read_uint64(argv[3], &wtx)) {
        fprintf(stderr, "Invalid wtx.\n");
        exit(EXIT_FAILURE);
    }

    uint64_t tout;
    if (!safe_read_uint64(argv[4], &tout)) {
        fprintf(stderr, "Invalid timeout.\n");
        exit(EXIT_FAILURE);
    }

    double perr;
    if (!safe_read_double(argv[5], &perr)) {
        fprintf(stderr, "Invalid perror.\n");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server = {
        .sin_family = AF_INET,
        .sin_addr = server_addr,
        .sin_port = htons(port)
    };

    // Setup socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1)
        logerr("Socket error");

    // Run client handler
    ExecutionLog xl = client_handler(&server, wtx, tout, perr);

    // Close connection
    close(sockfd);

    // Close file
    fclose(fin);

    // Measure end time
    clock_gettime(CLOCK_REALTIME, &end_time);

    // Get total time
    total_time = timespec_diff(&start_time, &end_time);

    // Client output
    /* printf("%zu %zu %zu %.3fs", xl.nmsg, nsent, xl.nerror, total_time); */

    return 0;
}
