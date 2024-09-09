#include <cassert>
#include <iostream>
#include <vector>

#include <stdio.h>
#include <strings.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>

#include "header.h"

#define LISTEN_LEN 5

static void fd_set_nb(int fd) {
  errno = 0;
  int flags = fcntl(fd, F_GETFL, 0);
  if (errno) {
    std::cout << "fd get flag fail." << std::endl;
    exit(-1);
  }
  flags |= O_NONBLOCK;
  fcntl(fd, F_SETFL, flags);
  if (errno) {
    std::cout << "fd set flag fail." << std::endl;
    exit(-1);
  }
}

// int handle_error(int ret) {
//   if (ret < 0) {
//     perror("deal error: ");
//     return -1;
//   }
//   if (ret == 0) {
//     std::cout << "client close the connection." << std::endl;
//     return 0;
//   }
//   return 1;
// }
//
// int handle(int conn_fd) {
//   char rbuf[MSG_LEN_SIZE + MAX_MSG_LEN + 1] = {0};
//   if (handle_error(read_full(conn_fd, rbuf, MSG_LEN_SIZE)) <= 0) {
//     return -1;
//   }
//   uint32_t msg_len = 0;
//   memcpy(&msg_len, rbuf, MSG_LEN_SIZE);
//   if (msg_len > MAX_MSG_LEN) {
//     std::cout << "msg too long." << std::endl;
//     return -1;
//   }
//   if (handle_error(read_full(conn_fd, rbuf + MSG_LEN_SIZE, msg_len)) <= 0) {
//     return -1;
//   }
//   rbuf[MSG_LEN_SIZE + msg_len] = 0;
//
//   // client say
//   std::cout << "[client]: " << rbuf+MSG_LEN_SIZE << std::endl;
//
//   // server reply
//   char wbuf[MSG_LEN_SIZE + MAX_MSG_LEN] = {0};
//   const char* reply = "world";
//   uint32_t wlen = strlen(reply);
//   memcpy(wbuf, &wlen, MSG_LEN_SIZE);
//   memcpy(wbuf+MSG_LEN_SIZE, reply, wlen);
//   if (handle_error(write_all(conn_fd, wbuf, wlen+MSG_LEN_SIZE)) <= 0) {
//     return -1;
//   }
//   return 0;
// }

enum {
  STATE_REQ = 0,
  STATE_RES = 1,
  STATE_END = 3
};

struct Conn {
  int fd = -1;
  uint32_t state = 0;
  size_t rbuf_size = 0;
  uint8_t rbuf[MSG_LEN_SIZE + MAX_MSG_LEN];
  size_t wbuf_size = 0;
  size_t wbuf_send = 0;
  uint8_t wbuf[MSG_LEN_SIZE + MAX_MSG_LEN];
};

static void state_req(Conn*);
static void state_res(Conn*);

static bool try_one_request(Conn* conn) {
  // try to parse a request from the buffer
  if (conn->rbuf_size < 4) {
    // not enough data in the buffer. Will retry in the next iteration
    return false;
  }
  uint32_t len = 0;
  memcpy(&len, &conn->rbuf[0], MSG_LEN_SIZE);
  if (len > MAX_MSG_LEN) {
    std::cout << "msg too long." << std::endl;
    conn->state = STATE_END;
    return false;
  }
  if (MSG_LEN_SIZE + len > conn->rbuf_size) {
    // not enough data in the buffer.
    return false;
  }
  printf("client say: %d, %s\n", len, &conn->rbuf[MSG_LEN_SIZE]);

  // generating echoing response
  memcpy(&conn->wbuf[0], &conn->rbuf[0], MSG_LEN_SIZE);
  memcpy(&conn->wbuf[MSG_LEN_SIZE], &conn->rbuf[MSG_LEN_SIZE], len);
  conn->wbuf_size = MSG_LEN_SIZE + len;

  size_t remain = conn->rbuf_size - MSG_LEN_SIZE - len;
  if (remain)
    memmove(conn->rbuf, &conn->rbuf[MSG_LEN_SIZE+len], remain);
  conn->rbuf_size = remain;
  conn->state = STATE_RES;
  state_res(conn);
  return (conn->state == STATE_REQ);
}

static bool try_fill_buffer(Conn* conn) {
  assert(conn->rbuf_size < sizeof(conn->rbuf));
  ssize_t rv = 0;
  do {
    size_t cap = sizeof(conn->rbuf) - conn->rbuf_size;
    rv = read(conn->fd, &conn->rbuf[conn->rbuf_size], cap);
  } while(rv < 0 && errno == EINTR);
  if (rv < 0 && errno == EAGAIN) {
    // got EAGAIN
    return false;
  }
  if (rv < 0) {
    // read error
    std::cout << "read() error. " << strerror(errno) << std::endl;
    conn->state = STATE_END;
    return false;
  }
  if (rv == 0) {
    if (conn->rbuf_size > 0) {
      std::cout << "unexpected EOF" << std::endl;
    } else {
      std::cout << "EOF" << std::endl;
    }
    conn->state = STATE_END;
    return false;
  }
  conn->rbuf_size += (size_t)rv;
  assert(conn->rbuf_size <= sizeof(conn->rbuf) - conn->rbuf_size);
  while(try_one_request(conn)) {}
  return (conn->state == STATE_REQ);
}

static void state_req(Conn* conn) {
  while(try_fill_buffer(conn)) {}
}

static bool try_flush_buffer(Conn* conn) {
  ssize_t rv = 0;
  do {
    size_t remain = conn->wbuf_size - conn->wbuf_send;
    rv = write(conn->fd, &conn->wbuf[conn->wbuf_send], remain);
  } while (rv < 0 && errno == EINTR);
  if (rv < 0 && errno == EAGAIN) {
    // got EAGAIN
    return false;
  }
  if (rv < 0) {
    std::cout << "write error. " << strerror(errno) << std::endl;
    conn->state = STATE_END;
    return false;
  }
  conn->wbuf_send += rv;
  assert(conn->wbuf_send <= conn->wbuf_size);
  if (conn->wbuf_send == conn->wbuf_size) {
    conn->state = STATE_REQ;
    conn->wbuf_size = conn->wbuf_send = 0;
    return false;
  }
  // still get some data in wbuf
  return true;
}

static void state_res(Conn* conn) {
  while(try_flush_buffer(conn)) {}
}

static void connection_io(Conn* conn) {
  if (conn->state == STATE_REQ) {
    state_req(conn);
  } else if (conn->state == STATE_RES) {
    state_res(conn);
  } else {
    assert(0);
  }
}

static void conn_put(std::vector<Conn*>& fd2Conn, Conn* conn) {
  if (fd2Conn.size() <= (size_t)conn->fd) {
    fd2Conn.resize(conn->fd + 1);
  }
  fd2Conn[conn->fd] = conn;
}

static int32_t accept_new_conn(std::vector<Conn*>& fd2Conn, int sock_fd) {
  struct sockaddr_in client_addr = {0};
  socklen_t socklen = sizeof(client_addr);
  int connfd = accept(sock_fd, (struct sockaddr*)&client_addr, &socklen);
  if (connfd < 0) {
    std::cout << "accept new conn fail." << strerror(errno) << std::endl;
    return -1;
  }
  fd_set_nb(connfd);
  Conn* conn = (Conn*)malloc(sizeof(Conn));
  if (!conn) {
    close(connfd);
    std::cout << "accept new conn fail." << "malloc fail." << std::endl;
    return -1;
  }
  conn->fd = connfd;
  conn->state = STATE_REQ;
  conn->rbuf_size = conn->wbuf_size = conn->wbuf_send = 0;
  conn_put(fd2Conn, conn);
  return 0;
}

int main() {
  int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (sock_fd < 0) {
    perror("socket create failed: ");
    return -1;
  }
  int val = 1;
  setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
  setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));

  struct sockaddr_in addr;
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(8080);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(sock_fd, (const sockaddr*)&addr, sizeof(addr)) < 0) {
    perror("bind failed: ");
    return -2;
  }
  if (listen(sock_fd, LISTEN_LEN) < 0) {
    perror("listen failed: ");
    return -3;
  }

  std::vector<Conn*> fd2Conn;
  fd_set_nb(sock_fd);
  std::vector<struct pollfd> poll_args;
  // event loop
  while(true) {
    poll_args.clear();
    struct pollfd pfd = {sock_fd, POLLIN, 0};
    poll_args.push_back(pfd);

    // make all need poll fds
    for (Conn* conn : fd2Conn) {
      if (!conn) {
        continue;
      }
      struct pollfd poll_fd = {};
      poll_fd.fd = conn->fd;
      poll_fd.events = (conn->state == STATE_REQ) ? POLLIN : POLLOUT;
      poll_fd.events = poll_fd.events | POLLERR;
      poll_args.push_back(poll_fd);
    }

    int recv = poll(poll_args.data(), (nfds_t)poll_args.size(), 1000);
    if (recv < 0) {
      std::cout << "poll failed." << std::endl;
      exit(-3);
    }

    for (int i = 1; i < poll_args.size(); i++) {
      if (poll_args[i].revents) {
        Conn* conn = fd2Conn[poll_args[i].fd];
        connection_io(conn);
        if (conn->state == STATE_END) {
          fd2Conn[conn->fd] = NULL;
          close(conn->fd);
          free(conn);
        }
      }
    }
    if (poll_args[0].revents) {
      accept_new_conn(fd2Conn, sock_fd);
    }
  }


  // struct sockaddr_in peer;
  // bzero(&peer, sizeof(peer));
  // socklen_t len = 0;
  //
  // while(true) {
  //   int conn_fd = accept(sock_fd, (sockaddr*)&peer, &len);
  //   if (conn_fd < 0) {
  //     perror("accept error: ");
  //     continue;
  //   }
  //   std::cout << "accept done: [" << inet_ntoa(peer.sin_addr) << ":" << ntohs(peer.sin_port)
  //             << "] fd: " << conn_fd << std::endl;
  //   while(true) {
  //     if (handle(conn_fd) < 0) break;
  //   }
  //   std::cout << "handle done: fd: " << conn_fd << std::endl;
  // }
  return 0;
}
