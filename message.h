#ifndef MESSAGE_H
#define MESSAGE_H
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdbool.h>
#define MESSAGE_CORRUPTION true
#define ACK_CORRUPTION true

// Bookkeeping
extern size_t nsent;
extern size_t nerror;

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

void alloc_message(Message*, size_t);
void fill_message(Message*, char*, size_t, uint64_t);
void fill_ack(AckMessage*, uint64_t);
void send_message(Message*, int, void*, double);
void send_ack(AckMessage*, int, struct sockaddr_in*, double);
bool recv_message(Message*, int, struct sockaddr_in*);
bool recv_ack(AckMessage*, int, void*);
void get_md5(char*, unsigned long, char*);
void free_message(Message *m);

#endif
