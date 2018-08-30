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
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/md5.h>
#define IDLE_TIMEOUT_SECS 60
#define IDLE_TIMEOUT_USECS 0
#define MAXLINE 65536
#define DEBUG true

// Handle errors from errno
extern int errno;
static inline void logerr(char *str) {
   perror(str);
   exit(EXIT_FAILURE);
}

// Message Structures
typedef struct Message {
    uint64_t seqnum;
    uint64_t sec;
    uint32_t nsec;
    uint16_t sz;
    char *buf;
    char md5[16];
} __attribute__((packed)) Message;

typedef struct AckMessage {
    uint64_t seqnum;
    uint64_t sec;
    uint32_t nsec;
    char md5[16];
} __attribute__((packed)) AckMessage;

// Sliding Window
typedef struct SlidingWindowElem {
    Message msg;
    struct SlidingWindowElem *next;
} SlidingWindowElem;

typedef struct SlidingWindow {
    struct SlidingWindowElem *first;
    struct SlidingWindowElem *last;
    uint64_t count;
    uint64_t width;
} SlidingWindow;

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
    if (sw->first == NULL) {
        free(sw);
        return;
    }

    SlidingWindowElem *aux = sw->first,
                      *ph;
    while (aux != NULL) {
        ph = aux->next;
        free(aux);
        aux = ph;
    }
}

// Integrity
void get_msg_md5(Message *msg, char *md5) {
    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, msg, 22);
    MD5_Update(&c, msg->buf, msg->sz);
    MD5_Final(md5, &c);
}

void get_ack_md5(AckMessage *ackmsg, char *md5) {
    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, ackmsg, 20);
    MD5_Final(md5, &c);
}

bool check_msg_md5(Message *msg) {
    char md5[16];
    get_msg_md5(msg, md5);
    return memcmp(msg->md5, md5, 16) == 0;
}

bool check_ack_md5(AckMessage *msg) {
    char md5[16];
    get_ack_md5(msg, md5);

    return memcmp(msg->md5, md5, 16) == 0;
}

// Safe send
uint32_t safe_send(int sockfd, void *buf, uint32_t total,
                   struct sockaddr *dest_addr) {
    ssize_t len;
    len = sendto(sockfd, buf, total, 0, dest_addr, sizeof(*dest_addr));

    if (len < 0) {
        close(sockfd);
        logerr("Send failed");
    } else if (len == 0) {
       close(sockfd);
       fprintf(stderr, "Server closed the connection during client send.\n");
       exit(EXIT_FAILURE);
    }

    return (uint32_t)len;
}

// Safe recv
uint32_t safe_recv(int sockfd, void *buf, uint32_t total,
                   struct sockaddr *src_addr) {
   ssize_t i = 0,
           len = 0;
   socklen_t addrlen = sizeof(*src_addr);

   for (; i < total &&
           (len = recvfrom(sockfd, buf + i, total - i, 0, src_addr, &addrlen)) > 0;
            i += len);

   if (len < 0) {
       close(sockfd);
       logerr("Receive failed");
   } else if (len == 0) {
       close(sockfd);
       fprintf(stderr, "Server closed the connection during client recv.\n");
       exit(EXIT_FAILURE);
   }

   return (uint32_t)i;
}

// Read ulong from char* safely
bool safe_read_long(char *str, unsigned long *num) {
    char *end;

    // Read decimal long
    errno = 0;
    *num = strtoul(str, &end, 10);

    // Check for strtol error conditions
    if (errno || end == str || *end != '\0')
        return false;

    return true;
}

// Read double from char* safely
bool safe_read_double(char *str, double *num) {
    char *end;

    // Read decimal long
    errno = 0;
    *num = strtod(str, &end);

    // Check for strtod error conditions
    if (errno || end == str || *end != '\0')
        return false;

    return true;
}

// Read uint16 from char* safely
bool safe_read_uint16(char *str, uint16_t *num) {
    unsigned long lnum;

    // Convert to uint16_t and store
    bool read_result = safe_read_long(str, &lnum);

    if (!read_result || lnum < 0 || lnum > UINT16_MAX)
        return false;

    *num = (uint16_t)lnum;
    return true;
}

// Read uint64 from char* safely
bool safe_read_uint64(char *str, uint64_t *num) {
    unsigned long lnum;

    // Convert to uint64_t and store
    bool read_result = safe_read_long(str, &lnum);

    if (!read_result || lnum < 0 || lnum > UINT64_MAX)
        return false;

    *num = (uint64_t)lnum;
    return true;
}

void send_message(Message m, int sockfd, void *addr) {
    char netbuf[MAXLINE+38];

    // Build frame
    uint64_t net_seqnum = (uint64_t)htonl(m.seqnum);
    uint64_t net_sec = (uint64_t)htonl(m.sec);
    uint32_t net_nsec = (uint32_t)htonl(m.nsec);
    uint16_t net_sz = (uint16_t)htons(m.sz);
    memcpy(netbuf, &net_seqnum, 8);
    memcpy(netbuf+8, &net_sec, 8);
    memcpy(netbuf+16, &net_nsec, 4);
    memcpy(netbuf+20, &net_sz, 2);
    memcpy(netbuf+22, m.buf, m.sz);
    memcpy(netbuf+22+m.sz, m.md5, 16);

    // Send frame header
    safe_send(sockfd, netbuf, 22, addr);

    // Send frame
    safe_send(sockfd, netbuf+22, m.sz+16, addr);
}

void recv_ack(AckMessage *am, int sockfd, void *addr) {
    char netbuf[36];

    // Recv ack
    safe_recv(sockfd, netbuf, 36, addr);

    // Populate struct
    memcpy(&am->seqnum, netbuf, 8);
    memcpy(&am->sec, netbuf+8, 8);
    memcpy(&am->nsec, netbuf+16, 4);
    memcpy(&am->md5, netbuf+20, 16);
}

// Client handler
void client_handler(int sockfd, FILE *fin,
                    void *server_addr, uint64_t width) {
    char buf[MAXLINE];

    SlidingWindow *window = make_sliding_window(width);

    Message m;
    AckMessage ack;

    struct timespec ts;
    uint64_t seqnum;
    bool locked;

    printf("Sending file...\n");
    while (fgets(buf, MAXLINE, fin)) {
        clock_gettime(CLOCK_REALTIME, &ts);

        // Create message
        m.seqnum = seqnum;
        m.sec = ts.tv_sec;
        m.nsec = ts.tv_nsec;
        m.sz = strlen(buf);
        m.buf = buf;
        get_msg_md5(&m, m.md5);

        // Put message into sliding window
        sliding_window_insert(window, m);

        // Send message
        send_message(m, sockfd, server_addr);
#ifdef DEBUG
        printf("[!] Sent message (seqnum=%u, len=%u)\n", m.seqnum, m.sz);
#endif

        seqnum++;

        // Block until ack of first element
        if (window->count == window->width) {
            locked = true;

            /* printf("window->count %u window->width %u\n", window->count, window->width); */
            while (locked) {
#ifdef DEBUG
                printf("[!] Window waiting for Ack with seqnum=%u\n",
                       window->first->next->msg.seqnum);
#endif
                recv_ack(&ack, sockfd, server_addr);
#ifdef DEBUG
                printf("[!] Ack (seqnum=%u)\n", ack.seqnum);
#endif
                if (check_ack_md5(&ack)
                      && ack.seqnum == window->first->next->msg.seqnum)
                    locked = false;
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

    // Setup timeout
    struct timeval timeout = {
        .tv_sec = IDLE_TIMEOUT_SECS,
        .tv_usec = IDLE_TIMEOUT_USECS
    };

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
        logerr("Setsockopt error");

    // Client handler
    client_handler(sockfd, fin, &server, wtx);

    /* fprintf("%d %d %d %.3fs", nmsg, nerror, time); */

    // Close connection
    close(sockfd);

    // Close file
    fclose(fin);

    return 0;
}
