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

int sockfd;
struct sockaddr_in server_addr;
uint16_t port;
uint64_t tout;
double perr;

size_t nsent;
size_t nerror;
pthread_mutex_t nsent_lock;
pthread_mutex_t nerror_lock;

// Client handler
size_t client_handler(FILE *fin, uint64_t width) {
    char buf[MAXLN];
    size_t nmsg = 0;
    SlidingWindow *window = make_sliding_window(width);

    Message m;

    AckMessage ack;

    uint64_t seqnum = 1;
    bool corrupt;

#if DEBUG
    printf("[!] Sending file...\n");
#endif
    while (fgets(buf, MAXLN, fin)) {
        size_t msg_len = strlen(buf);

        // Strip newline
        buf[msg_len-1] = '\0';
        msg_len--;

        // Print log line
#if !DEBUG
        printf("%s\n", buf);
#endif

        // Increment message count
        nmsg += 1;

        // Allocate space for message
        alloc_message(&m, msg_len);

        // Fill message
        fill_message(&m, buf, msg_len, seqnum);

        // Put message into sliding window
        sliding_window_insert(window, &m);

        // Send message
        send_message(&m, sockfd, &server_addr, perr);

        // Set ack timeout
        create_ack_timer(window->last);
        set_ack_timeout(window->last, tout);

        seqnum++;

        // Block until ack of first element when window full
        if (window->count == window->width-1) {
            while (!window->first->acked) {
#if DEBUG
                printf("[!] Window waiting for Ack %lu\n",
                       window->first->msg.seqnum);
#endif
                if (recv_ack(&ack, sockfd, &server_addr)) {
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
    while (window->first != NULL) {
        while (!window->first->acked) {
#if DEBUG
            printf("[!] Window waiting for Ack %lu\n",
                   window->first->msg.seqnum);
#endif
            if (recv_ack(&ack, sockfd, &server_addr)) {
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

    // Return number of distinct messages
    return nmsg;
}

int main(int argc, char *argv[]) {
    struct timespec start_time, end_time;
    struct in_addr server_ip;
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
    FILE *fin = fopen(argv[1], "r");

    if (!fin) {
        fprintf(stderr, "Could not open input file '%s'.\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    // Disable buffering in output file
    setbuf(fin, NULL);

    char *ip_str = strtok(argv[2], ":");
    char *port_str = strtok(NULL, ":");

    // Setup target address
    inet_pton(AF_INET, ip_str, &server_ip);

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

    if (!safe_read_uint64(argv[4], &tout)) {
        fprintf(stderr, "Invalid timeout.\n");
        exit(EXIT_FAILURE);
    }

    if (!safe_read_double(argv[5], &perr)) {
        fprintf(stderr, "Invalid perror.\n");
        exit(EXIT_FAILURE);
    }

    // Setup server addr
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr = server_ip;
    server_addr.sin_port = htons(port);

    // Setup socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1)
        logerr("Socket error");

    // Setup locks for shared vars
    pthread_mutex_init(&nsent_lock, NULL);
    pthread_mutex_init(&nerror_lock, NULL);

    // Run client handler
    size_t nmsg = client_handler(fin, wtx);

    // Close connection
    close(sockfd);

    // Close file
    fclose(fin);

    // Measure end time
    clock_gettime(CLOCK_REALTIME, &end_time);

    // Get total time
    total_time = timespec_diff(&start_time, &end_time);

    // Client output
    printf("%zu %zu %zu %.3fs\n", nmsg, nsent, nerror, total_time);

    return 0;
}
