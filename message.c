#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/md5.h>
#include "utils.h"
#include "message.h"

extern size_t nsent;

// Alloc space for message
void alloc_message(Message *m, size_t size) {
    m->buf = (char*)malloc(size*sizeof(char));
}

// Fill message
void fill_message(Message *m, char *buf, uint64_t seqnum) {
    struct timespec ts;
    size_t sz = strlen(buf);
    memcpy(m->buf, buf, sz);

    clock_gettime(CLOCK_REALTIME, &ts);

    m->seqnum = seqnum;
    m->sec = ts.tv_sec;
    m->nsec = ts.tv_nsec;
    m->sz = sz;
}

// Fill ack
void fill_ack(AckMessage *am, uint64_t seqnum) {
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);

    am->seqnum = seqnum;
    am->sec = ts.tv_sec;
    am->nsec = ts.tv_nsec;
}

// Send message
void send_message(Message *m, int sockfd, void *addr) {
    char netbuf[MAXLN+38];

    // Build frame
    uint64_t net_seqnum = (uint64_t)htobe64(m->seqnum);
    uint64_t net_sec = (uint64_t)htobe64(m->sec);
    uint32_t net_nsec = (uint32_t)htonl(m->nsec);
    uint16_t net_sz = (uint16_t)htons(m->sz);
    memcpy(netbuf, &net_seqnum, 8);
    memcpy(netbuf+8, &net_sec, 8);
    memcpy(netbuf+16, &net_nsec, 4);
    memcpy(netbuf+20, &net_sz, 2);
    memcpy(netbuf+22, m->buf, m->sz);

    get_md5(netbuf, 22+m->sz, m->md5);
    memcpy(netbuf+22+m->sz, m->md5, 16);

    // Send all
    safe_send(sockfd, netbuf, 22+m->sz+16, addr);
#if DEBUG
    printf("[!] Sent message (seqnum=%u, len=%u)\n", m->seqnum, m->sz);
#endif
}

// Send ack
void send_ack(AckMessage *am, int sockfd, struct sockaddr_in *addr) {
    char netbuf[36];

    // Populate struct
    uint64_t net_seqnum = (uint64_t)htobe64(am->seqnum);
    uint64_t net_sec = (uint64_t)htobe64(am->sec);
    uint32_t net_nsec = (uint32_t)htonl(am->nsec);
    memcpy(netbuf, &net_seqnum, 8);
    memcpy(netbuf+8, &net_sec, 8);
    memcpy(netbuf+16, &net_nsec, 4);

    get_md5(netbuf, 20, am->md5);
    memcpy(netbuf+20, am->md5, 16);

    // Send ack
    safe_send(sockfd, netbuf, 36, addr);
}

// Receive valid message
bool recv_message(Message *m, int sockfd, struct sockaddr_in *addr) {
    char netbuf[MAXLN+38];

    // Get message header
    safe_recv(sockfd, netbuf, 22, addr);

    memcpy(&m->seqnum, netbuf, 8);
    memcpy(&m->sec, netbuf+8, 8);
    memcpy(&m->nsec, netbuf+16, 4);
    memcpy(&m->sz, netbuf+20, 2);
    m->seqnum = (uint64_t)be64toh(m->seqnum);
    m->sec = (uint64_t)be64toh(m->sec);
    m->nsec = (uint32_t)ntohl(m->nsec);
    m->sz = (uint16_t)ntohs(m->sz);

    // Get message
    safe_recv(sockfd, netbuf+22, m->sz+16, addr);
#if DEBUG
    printf("[!] Message %u (len=%u)\n", m->seqnum, m->sz);
#endif

    memcpy(m->buf, netbuf+22, m->sz);
    memcpy(m->md5, netbuf+22+m->sz, 16);

    unsigned char md5[16];
    get_md5(netbuf, 22+m->sz, md5);
    return memcmp(m->md5, md5, 16) == 0;
}

// Receive valid ack
bool recv_ack(AckMessage *am, int sockfd, void *addr) {
    char netbuf[36];

    // Recv ack
    safe_recv(sockfd, netbuf, 36, addr);

    // Populate struct
    memcpy(&am->seqnum, netbuf, 8);
    memcpy(&am->sec, netbuf+8, 8);
    memcpy(&am->nsec, netbuf+16, 4);
    memcpy(&am->md5, netbuf+20, 16);
    am->seqnum = (uint64_t)be64toh(am->seqnum);
    am->sec = (uint64_t)be64toh(am->sec);
    am->nsec = (uint32_t)ntohl(am->nsec);
#if DEBUG
    printf("[!] Ack %u (at %u)\n", am->seqnum, am->sec);
#endif

    unsigned char md5[16];
    get_md5(netbuf, 20, md5);
    return memcmp(am->md5, md5, 16) == 0;
}

// Integrity
void get_md5(char *data, unsigned long size, char *md5) {
    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, data, size);
    MD5_Final(md5, &c);
}

// Memory
void free_message(Message *m) {
    if (m->buf != NULL)
        free(m->buf);
}
