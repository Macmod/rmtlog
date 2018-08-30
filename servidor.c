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
#include <openssl/md5.h>
#define DEBUG true
#define INADDR "127.0.0.1"
#define MAX_PENDING_CONNS 10
#define IDLE_TIMEOUT_SECS 15
#define IDLE_TIMEOUT_USECS 0
#define CLIENT_TIMEOUT_SECS 5
#define CLIENT_TIMEOUT_USECS 0
#define MAXLINE 65536
#define addr_cmp(a,b) (((a).sin_addr.s_addr == (b).sin_addr.s_addr) && ((a).sin_port == (b).sin_port))

// Handle errors from errno
extern int errno;
static inline void logerr_thr(char *str) {
   perror(str);
   pthread_exit(NULL);
}

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

// Client list
typedef struct Client {
    struct sockaddr_in addr_id;

    SlidingWindow *sw;
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
            free_sliding_window(aux->sw);
            free(aux);
        }

        prev = aux;
        aux = aux->next;
    }
}

Client *insert_client(ClientList *cl, struct sockaddr_in addr, uint64_t width) {
    Client *c = (Client*)malloc(sizeof(Client));
    c->addr_id = addr;
    c->sw = make_sliding_window(width);

    c->next = NULL;
    if (cl->last == NULL) {
        cl->first = c;
    } else {
        cl->last->next = c;
    }

    cl->last = c;
    return c;
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
                   struct sockaddr_in *dest_addr) {
    ssize_t len;
    len = sendto(sockfd, buf, total, 0,
                 (struct sockaddr*)dest_addr, sizeof(struct sockaddr_in));

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
                   struct sockaddr_in *src_addr) {
   ssize_t i = 0,
           len = 0;
   socklen_t addrlen = sizeof(*src_addr);

   for (; i < total &&
           (len = recvfrom(sockfd, buf + i, total - i, 0,
                           (struct sockaddr*)src_addr, &addrlen)) > 0;
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

// Receive message
void recv_message(Message *m, int sockfd, struct sockaddr_in *addr) {
    char netbuf[MAXLINE+38];

    // Get message header
    safe_recv(sockfd, netbuf, 22, addr);

    memcpy(&m->seqnum, netbuf, 8);
    memcpy(&m->sec, netbuf+8, 8);
    memcpy(&m->nsec, netbuf+16, 4);
    memcpy(&m->sz, netbuf+20, 2);
    m->seqnum = (uint64_t)ntohl(m->seqnum);
    m->sec = (uint64_t)ntohl(m->sec);
    m->nsec = (uint32_t)ntohl(m->nsec);
    m->sz = (uint16_t)ntohs(m->sz);

    // Get message
    safe_recv(sockfd, netbuf+22, m->sz+16, addr);
#ifdef DEBUG
    printf("[!] Message (seqnum=%u, len=%u)\n", m->seqnum, m->sz);
#endif

    m->buf = (char*)malloc(m->sz);
    memcpy(m->buf, netbuf+22, m->sz);
    memcpy(m->md5, netbuf+22+m->sz, 16);
}

// Handle ack
AckMessage make_ack(uint64_t seqnum) {
    struct timespec ts;
    AckMessage am;

    clock_gettime(CLOCK_REALTIME, &ts);
    am.seqnum = seqnum;
    am.sec = ts.tv_sec;
    am.nsec = ts.tv_nsec;
    get_ack_md5(&am, am.md5);

    return am;

}

void send_ack(AckMessage *am, int sockfd, struct sockaddr_in *addr) {
    char netbuf[36];

    // Populate struct
    memcpy(netbuf, &am->seqnum, 8);
    memcpy(netbuf+8, &am->sec, 8);
    memcpy(netbuf+16, &am->nsec, 4);
    memcpy(netbuf+20, &am->md5, 16);

    // Send ack
    safe_send(sockfd, netbuf, 36, addr);
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
        printf("--- %s:%u\n", inet_ntoa(addr.sin_addr), addr.sin_port);
#endif
        if (!find_client(&clist, addr, &cptr)) {
#ifdef DEBUG
            printf("--- New client\n");
#endif
            cptr = insert_client(&clist, addr, wrx);
        } else {
#ifdef DEBUG
            printf("--- Existing client\n");
#endif
        }

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
