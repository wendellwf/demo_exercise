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

// static int32_t send_req(int fd, const char* text) {
//     uint32_t w_msg_len = strlen(text);
//     if (w_msg_len > MAX_MSG_LEN) {
//         std::cout << "msg too long" << std::endl;
//         return -1;
//     }
//     char wbuf[MSG_LEN_SIZE + MAX_MSG_LEN];
//     memcpy(wbuf, &w_msg_len, MSG_LEN_SIZE);
//     memcpy(wbuf+MSG_LEN_SIZE, text, w_msg_len);
//     if (handle_error(write_all(fd, wbuf, w_msg_len + MSG_LEN_SIZE)) <= 0) {
//         perror("write error: ");
//         return -1;
//     }
//     return 0;
// }
//
// static int32_t read_res(int fd) {
//     uint32_t r_msg_len = 0;
//     char rbuf[MSG_LEN_SIZE + MAX_MSG_LEN + 1] = {0};
//     if (handle_error(read_full(fd, rbuf, MSG_LEN_SIZE)) <= 0) {
//         perror("read msg_len error: ");
//         return -1;
//     }
//     memcpy(&r_msg_len, rbuf, MSG_LEN_SIZE);
//     if (r_msg_len > MAX_MSG_LEN) {
//         std::cout << "read msg length too long" << std::endl;
//         return -1;
//     }
//     if (handle_error(read_full(fd, rbuf+ MSG_LEN_SIZE, r_msg_len)) <= 0) {
//         perror("read msg error: ");
//         return -1;
//     }
//     rbuf[MSG_LEN_SIZE + r_msg_len] = 0;
//     std::cout << "server reply: " << rbuf + MSG_LEN_SIZE << std::endl;
//     return 0;
// }

static int32_t send_req(int fd, const std::vector<std::string>& cmd) {
    uint32_t len = 4;
    for (const auto& s : cmd) {
        len = 4 + s.size();
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
    rbuf[MSG_LEN_SIZE + len] = 0;
    uint32_t rescode = 0;
    memcpy(&rescode, &rbuf[MSG_LEN_SIZE], RESP_CODE_SIZE);
    printf("server reply: [%u] %d %s\n", rescode, len-4, &rbuf[MSG_LEN_SIZE+RESP_CODE_SIZE]);
    return 0;
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
    // const char* query_list[3] = {"hello1", "hello2", "hello3"};
    // for (int i = 0; i < 3; i++) {
    //     int32_t err = send_req(conn_fd, query_list[i]);
    //     if (err) goto L_DONE;
    // }
    //
    // for (int i = 0; i < 3; i++) {
    //     int32_t err = read_res(conn_fd);
    //     if (err) goto L_DONE;
    // }
    std::vector<std::string> cmd;
    for (int i = 1; i < argc; i++) {
        cmd.emplace_back(argv[i]);
    }
    int32_t err = send_req(conn_fd, cmd);
    if (err) {
        goto L_DONE;
    }
    err = read_res(conn_fd);
    if (err) {
        goto L_DONE;
    }

L_DONE:
    close(conn_fd);
    return 0;
}
