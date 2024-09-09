//
// Created by wendell on 2024/9/2.
//

#ifndef HEADER_H
#define HEADER_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define MSG_LEN_SIZE 4
#define MAX_MSG_LEN 4096
#define RESP_CODE_SIZE 4

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

#endif //HEADER_H
