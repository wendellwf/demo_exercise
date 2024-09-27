//
// Created by wendell on 2024/9/26.
//

#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

#define container_of(ptr, type, member) ({                  \
    const typeof( ((type *)0)->member )* __mptr = (ptr);    \
    (type *)( (char *)__mptr - offsetof(type, member) );})

inline uint64_t str_hash(const uint8_t* data, size_t len) {
    uint32_t h = 0x811C9DC5;
    for (size_t i = 0; i < len; i++) {
        h = (h+data[i]) * 0x01000193;
    }
    return h;
}

enum {
    SER_NIL = 0,
    SER_ERR = 1,
    SER_STR = 2,
    SER_INT = 3,
    SER_DBL = 4,
    SER_ARR = 5,
};

#define LISTEN_LEN 5 // listen list queue size

#define CMD_NUMBER_SIZE 4 // data serialization number field size
#define CMD_LEN_SIZE 4 // data serialization number field size
#define MSG_LEN_SIZE 4 // data serialization msg_len field size
#define RESP_CODE_SIZE 4 // response data serialization response_code field size
#define MAX_MSG_LEN 4096 // data serialization msg max len

int32_t read_full(int fd, char* rbuf, size_t len) {
    int sz = len;
    while(sz > 0) {
        int rlen = read(fd, rbuf, sz);
        if (rlen <= 0) {
            return rlen;
        }
        sz -= rlen;
        rbuf += rlen;
    }
    return len;
}

int32_t write_all(int fd, const char* wbuf, size_t len) {
    int sz = len;
    while(sz > 0) {
        int wlen = write(fd, wbuf, sz);
        if (wlen <= 0) {
            return wlen;
        }
        sz -= wlen;
        wbuf += wlen;
    }
    return len;
}

#endif //COMMON_H
