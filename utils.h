#ifndef UTILS_H
#define UTILS_H
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <errno.h>
#define MAXLINE 65536

// Handle errors from errno
static inline void logerr_thr(char *str) {
   perror(str);
   pthread_exit(NULL);
}

static inline void logerr(char *str) {
   perror(str);
   exit(EXIT_FAILURE);
}

uint32_t safe_send(int, void*, uint32_t, struct sockaddr_in*);
uint32_t safe_recv(int, void*, uint32_t, struct sockaddr_in*);
bool safe_read_long(char*, unsigned long*);
bool safe_read_double(char*, double*);
bool safe_read_uint16(char*, uint16_t*);
bool safe_read_uint64(char*, uint64_t*);

#endif
