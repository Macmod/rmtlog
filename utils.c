#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>
#include "utils.h"

// Safe send
uint32_t safe_send(int sockfd, void *buf, uint32_t total,
                   struct sockaddr_in *dest_addr) {
    ssize_t len;
    len = sendto(sockfd, buf, total, 0, (struct sockaddr*)dest_addr, sizeof(*dest_addr));

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
           (len = recvfrom(sockfd, buf + i, total - i, 0, (struct sockaddr*)src_addr, &addrlen)) > 0;
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

double timespec_diff(struct timespec *start, struct timespec *end) {
    struct timespec diff;
    double result;

    if ((end->tv_nsec - start->tv_nsec) < 0) {
        diff.tv_sec = end->tv_sec - start->tv_sec - 1;
        diff.tv_nsec = end->tv_nsec - start->tv_nsec + 1000000000;
    } else {
        diff.tv_sec = end->tv_sec - start->tv_sec;
        diff.tv_nsec = end->tv_nsec - start->tv_nsec;
    }

    result = diff.tv_sec + diff.tv_nsec/1000000000;
    return result;
}
