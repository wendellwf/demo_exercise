//
// Created by wendell on 2024/8/31.
//

#include <iostream>
#include <vector>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <strings.h>
#include <unistd.h>

#include "header.h"

#define CMD_NUMBER_SIZE 4
#define CMD_LEN_SIZE 4

int handle_error(int ret) {
    if (ret < 0) {
        perror("deal error: ");
        return -1;
    }
    if (ret == 0) {
        std::cout << "client close this connection." << std::endl;
        return 0;
    }
    return 1;
}

static void msg(const char *msg) {
    fprintf(stderr, "%s\n", msg);
}


/**
*  +------+------+-----+------+-----+------+-----+-----+------+
*  | alen | nstr | len | str1 | len | str2 | ... | len | strn |
*  +------+------+-----+------+-----+------+-----+-----+------+
*  alen => the length of the client send raw string (32-bit integers)
*  nstr => the number of strings (32-bit integers)
*  len => the length of the following string (32-bit integers)
*
*  unserilize: show the message structure
*/
static void unserilize(char* buffer) {
    printf("++++++++++unserilize++++++++++++\n");
    uint32_t len = 0;
    uint32_t num = 0;
    memcpy(&len, &buffer[0], MSG_LEN_SIZE);
    memcpy(&num, &buffer[MSG_LEN_SIZE], CMD_NUMBER_SIZE);
    printf("buffer: len: %u, cmd_number: %u\n", len, num);

    uint32_t cur = MSG_LEN_SIZE + CMD_NUMBER_SIZE;
    while (cur < len) {
        uint32_t cmd_len = 0;
        char cmd[1024] = {0};
        memcpy(&cmd_len, &buffer[cur], CMD_LEN_SIZE);
        cur += CMD_LEN_SIZE;
        memcpy(cmd, &buffer[cur], cmd_len);
        printf("\tcmd_len: %u, cmd: %s\n", cmd_len, cmd);
        cur += cmd_len;
    }
    printf("+++++++++++++++++++++++++++++++++\n");
}

static int32_t send_req(int fd, const std::vector<std::string>& cmd) {
    uint32_t len = 4;
    for (const auto& s : cmd) {
        len += 4 + s.size();
    }
    if (len > MAX_MSG_LEN) {
        std::cout << "msg too long" << std::endl;
        return -1;
    }

    char wbuf[MSG_LEN_SIZE + MAX_MSG_LEN];
    memcpy(wbuf, &len, MSG_LEN_SIZE);
    uint32_t n = cmd.size();
    memcpy(wbuf+MSG_LEN_SIZE, &n, CMD_NUMBER_SIZE);
    size_t cur = MSG_LEN_SIZE + CMD_NUMBER_SIZE;
    for (const std::string& s : cmd) {
        uint32_t p = (uint32_t)s.size();
        memcpy(&wbuf[cur], &p, CMD_LEN_SIZE);
        memcpy(&wbuf[cur + CMD_LEN_SIZE], s.data(), s.size());
        cur += 4 + s.size();
    }
    return write_all(fd, wbuf, 4+len);
}

enum {
    SER_NIL = 0,
    SER_ERR = 1,
    SER_STR = 2,
    SER_INT = 3,
    SER_ARR = 4,
};

static int32_t on_response(const uint8_t* data, size_t size) {
    if (size < 1) {
        msg("bad response");
        return -1;
    }
    switch(data[0]) {
        case SER_NIL:
            printf("(nil)\n");
            return 1;
        case SER_ERR:
            if (size < 1 + 8) {
                msg("bad response");
                return -1;
            }
            {
            int32_t code = 0;
            uint32_t len = 0;
            memcpy(&code, &data[1], 4);
            memcpy(&len, &data[1+4], 4);
            if (size < 1 + 8 + len) {
                msg("bad response");
                return -1;
            }
            printf("(err) %d %u %s\n", code, len, &data[1+8]);
            return 1 + 8 + len;
            }
        case SER_STR:
            if (size < 1 + 4) {
                msg("bad response");
                return -1;
            }
            {
            uint32_t len = 0;
            memcpy(&len, &data[1], 4);
            if (size < 1 + 4 + len) {
                msg("bad response");
                return -1;
            }
            printf("(str) %.*s\n", len, &data[1+4]);
            return 1 + 4 + len;
            }
        case SER_INT:
            if (size < 1 + 8) {
                msg("bad response");
                return -1;
            }
            {
            int64_t val = 0;
            memcpy(&val, &data[1], 8);
            printf("(int) %ld\n", val);
            return 1 + 8;
            }
        case SER_ARR:
            if (size < 1 + 4) {
                msg("bad response");
                return -1;
            }
            {
            uint32_t len = 0;
            memcpy(&len, &data[1], 4);
            printf("(arr) len=%u\n", len);
            size_t arr_bytes = 1 + 4;
            for (uint32_t i = 0; i < len; ++i) {
                int32_t rv = on_response(&data[arr_bytes], size - arr_bytes);
                if (rv < 0) {
                    return rv;
                }
                printf("(arr) end\n");
                return (int32_t)arr_bytes;
            }
            }
        default:
            msg("bad response");
            return -1;
    }
}

static int32_t read_res(int fd) {
    uint32_t len = 0;
    char rbuf[MSG_LEN_SIZE + MAX_MSG_LEN + 1] = {0};
    if (handle_error(read_full(fd, rbuf, MSG_LEN_SIZE)) <= 0) {
        perror("read msg_len error: ");
        return -1;
    }
    memcpy(&len, rbuf, MSG_LEN_SIZE);
    if (len > MAX_MSG_LEN) {
        std::cout << "read msg length too long" << std::endl;
        return -1;
    }
    if (handle_error(read_full(fd, rbuf+ MSG_LEN_SIZE, len)) <= 0) {
        perror("read msg error: ");
        return -1;
    }
    // rbuf[MSG_LEN_SIZE + len] = 0;
    // uint32_t rescode = 0;
    // memcpy(&rescode, &rbuf[MSG_LEN_SIZE], RESP_CODE_SIZE);
    // printf("server reply: [%u] %d %s\n", rescode, len-4, &rbuf[MSG_LEN_SIZE+RESP_CODE_SIZE]);
    int32_t rv = on_response((uint8_t*)&rbuf[4], len);
    if (rv > 0 && (uint32_t)rv != len) {
        msg("bad response");
        rv = -1;
    }
    return rv;
}





int main(int argc, char** argv) {
    // todo: check argv
    int conn_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn_fd < 0) {
        perror("create socket error: ");
        return -1;
    }
    struct sockaddr_in remote;
    bzero(&remote, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_port = htons(8080);
    remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(conn_fd, (const struct sockaddr*)&remote, sizeof(remote)) < 0) {
        perror("connect error: ");
        return -2;
    }
    std::vector<std::string> cmd;
    for (int i = 1; i < argc; i++) {
        cmd.emplace_back(argv[i]);
    }
    int32_t err = send_req(conn_fd, cmd);
    if (err < 0) {
        std::cout << "send_req err" << std::endl;
        goto L_DONE;
    }
    err = read_res(conn_fd);
    if (err < 0) {
        std::cout << "read_res err" << std::endl;
        goto L_DONE;
    }

L_DONE:
    close(conn_fd);
    return 0;
}
