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
#include "slidingwindow.h"
#define DEBUG true

// Ack timeout
void ack_timeout(union sigval arg) {
    Message *msg = arg.sival_ptr;

#ifdef DEBUG
    printf("[!] Ack for %u timed out! Retransmitting...\n", msg->seqnum);
#endif

    /* send_message(m, sockfd, msg->addr); */
#ifdef DEBUG
    printf("[!] Retransmitted message (seqnum=%u, len=%u)\n", msg->seqnum, msg->sz);
#endif

    /* set_ack_timeout(m, tout); */
}

// Unset ack reception timeout
void unset_ack_timeout(SlidingWindowElem *swe) {
    if (swe->timer == NULL)
        return;

    int status;
    struct itimerspec ts;

    ts.it_value.tv_sec = 0;
    ts.it_value.tv_nsec = 0;
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;

    status = timer_settime(swe->timer, 0, &ts, 0);
    if (status == -1)
        logerr("Timer disarming error");
}

// Setup ack reception timeout
void set_ack_timeout(SlidingWindowElem *swe, uint64_t tout) {
    timer_t timer_id;
    int status;
    struct itimerspec ts;
    struct sigevent se;

    se.sigev_notify = SIGEV_THREAD;
    se.sigev_value.sival_ptr = (void*)swe;
    se.sigev_notify_function = ack_timeout;
    se.sigev_notify_attributes = NULL;

    ts.it_value.tv_sec = tout;
    ts.it_value.tv_nsec = 0;
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;

    status = timer_create(CLOCK_REALTIME, &se, &timer_id);
    if (status == -1)
        logerr("Timer creation error");

    status = timer_settime(timer_id, 0, &ts, 0);
    if (status == -1)
        logerr("Timer arming error");

    swe->timer = timer_id;
}

// Client handler
void client_handler(int sockfd, FILE *fin, void *server_addr,
                    uint64_t width, uint64_t tout) {
    char buf[MAXLINE];

    SlidingWindow *window = make_sliding_window(width);

    Message m;
    AckMessage ack;

    uint64_t seqnum;
    bool locked;

#ifdef DEBUG
    printf("[!] Sending file...\n");
#endif
    while (fgets(buf, MAXLINE, fin)) {
        // Make message
        m = make_message(buf, seqnum);

        // Put message into sliding window
        sliding_window_insert(window, m);

        // Send message
        send_message(m, sockfd, server_addr);
#ifdef DEBUG
        printf("[!] Sent message (seqnum=%u, len=%u)\n", m.seqnum, m.sz);
#endif

        // Set ack timeout
        set_ack_timeout(window->last, tout);

        seqnum++;

        // Block until ack of first element
        if (window->count == window->width) {
            locked = true;

            while (locked) {
#ifdef DEBUG
                printf("[!] Window waiting for Ack with seqnum=%u\n",
                       window->first->next->msg.seqnum);
#endif
                recv_ack(&ack, sockfd, server_addr);
#ifdef DEBUG
                printf("[!] Ack (seqnum=%u)\n", ack.seqnum);
#endif
                if (check_ack_md5(&ack)) {
#ifdef DEBUG
                    printf("--- MD5: OK\n");
#endif
                    if (ack.seqnum == window->first->next->msg.seqnum)
                        locked = false;
                } else {
#ifdef DEBUG
                    printf("--- MD5: CORRUPT\n");
#endif
                }
            }
        }
    }

    free_sliding_window(window);
}

int main(int argc, char *argv[]) {
    // Disable stdout buffering
    setvbuf(stdout, NULL, _IONBF, 0);

    // Help
    if (argc < 6) {
        fprintf(stderr,
                "Usage: %s <file> <ip>:<port> <wtx> <tout> <perror>\n",
                argv[0]);
        exit(EXIT_FAILURE);
    }

    int sockfd;
    uint16_t port;
    struct in_addr server_addr;
    struct sockaddr_in client;

    // Parse args
    FILE *fin = fopen(argv[1], "r");

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

    // Client handler
    client_handler(sockfd, fin, &server, wtx, tout);

    /* fprintf("%d %d %d %.3fs", nmsg, nerror, time); */

    // Close connection
    close(sockfd);

    // Close file
    fclose(fin);

    return 0;
}
