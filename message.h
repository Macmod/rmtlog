#ifndef MESSAGE_H
#define MESSAGE_H
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdbool.h>

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

Message make_message(char*, uint64_t);
AckMessage make_ack(uint64_t);
void send_message(Message, int, void*);
void send_ack(AckMessage*, int, struct sockaddr_in*);
void recv_message(Message*, int, struct sockaddr_in*);
void recv_ack(AckMessage*, int, void*);
void get_msg_md5(Message *msg, char *md5);
void get_ack_md5(AckMessage *ackmsg, char *md5);
bool check_msg_md5(Message *msg);
bool check_ack_md5(AckMessage *msg);

#endif
