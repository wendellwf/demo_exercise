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
#include <map>
#include <poll.h>

#include "header.h"
#include "hashtable.h"

#define LISTEN_LEN 5

#define CMD_NUMBER_SIZE 4
#define CMD_LEN_SIZE 4

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
static void unserilize(const char* buffer) {
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

/**
*  +------+-----+------+-----+------+-----+-----+------+
*  | nstr | len | str1 | len | str2 | ... | len | strn |
*  +------+-----+------+-----+------+-----+-----+------+
*  nstr => the number of strings (32-bit integers)
*  len => the length of the following string (32-bit integers)
*/
static int32_t parse_req(const uint8_t* data, size_t len, std::vector<std::string>& out) {
  if (len < 4) {
    return -1;
  }
  uint32_t n = 0; // cmd number
  memcpy(&n, &data[0], CMD_NUMBER_SIZE);
  if (n > 4) {
    return -1;
  }
  size_t pos = MSG_LEN_SIZE;
  while (n--) {
    if (pos + MSG_LEN_SIZE > len) {
      return -1;
    }
    uint32_t sz = 0;
    memcpy(&sz, &data[pos], CMD_LEN_SIZE);
    if (pos + 4 + sz > len) {
      return -1;
    }
    out.push_back(std::string((char*)&data[pos+CMD_LEN_SIZE], sz));
    pos += 4 + sz;
  }
  if (pos != len) {
    return -1; // trailing garbage
  }
  return 0;
}

enum {
  RES_OK = 0,
  RES_ERR = 1,
  RES_NX = 2,
};

// the structure from the key
struct Entry {
  struct HNode node;
  std::string key;
  std::string val;
};

// the data structure for the key space
static struct {
  HMap db;
} g_data;

#define container_of(ptr, type, member) ({ \
  const typeof( ((type*)0)->member) *__mptr = (ptr); \
  (type*)( (char*)__mptr - offsetof(type, member) ); })

static uint64_t str_hash(const uint8_t *data, size_t len) {
  uint32_t h = 0x811C9DC5;
  for (size_t i = 0; i < len; i++) {
    h = (h + data[i]) * 0x01000193;
  }
  return h;
}

static bool entry_eq(HNode* lhs, HNode* rhs) {
  struct Entry* le = container_of(lhs, struct Entry, node);
  struct Entry* re = container_of(rhs, struct Entry, node);
  return lhs->hcode == rhs->hcode && le->key == re->key;
}

static uint32_t do_get(std::vector<std::string>& cmd, uint8_t* res, uint32_t* reslen) {
  Entry key;
  key.key.swap(cmd[1]);
  key.node.hcode = str_hash((uint8_t*)key.key.data(), key.key.size());

  HNode* node = hm_lookup(&g_data.db, &key.node, &entry_eq);
  if (!node) {
    return RES_NX;
  }
  const std::string& val = container_of(node, Entry, node)->val;
  assert(val.size() <= MAX_MSG_LEN);
  memcpy(res, val.data(), val.size());
  *reslen = (uint32_t)val.size();
  return RES_OK;
}

static uint32_t do_set(std::vector<std::string>& cmd, uint8_t* res, uint32_t* reslen) {
  (void)res;
  (void)reslen;

  Entry key;
  key.key.swap(cmd[1]);
  key.node.hcode = str_hash((uint8_t*)key.key.data(), key.key.size());

  HNode* node = hm_lookup(&g_data.db, &key.node, &entry_eq);
  if (node) {
    container_of(node, Entry, node)->val.swap(cmd[2]);
  } else {
    Entry* ent = new Entry();
    ent->key.swap(key.key);
    ent->node.hcode = key.node.hcode;
    ent->val.swap(cmd[2]);
    hm_insert(&g_data.db, &ent->node);
  }
  return RES_OK;
}

static uint32_t do_del(std::vector<std::string>& cmd, uint8_t* res, uint32_t* reslen) {
  (void)res;
  (void)reslen;

  Entry key;
  key.key.swap(cmd[1]);
  key.node.hcode = str_hash((uint8_t*)key.key.data(), key.key.size());

  HNode* node = hm_pop(&g_data.db, &key.node, &entry_eq);
  if (node) {
    delete container_of(node, Entry, node);
  }
  return RES_OK;
}

static bool cmd_is(const std::string& in, const std::string& cmd) {
  return (in == cmd);
}

static int32_t do_request(const uint8_t* req, uint32_t reqlen,
      uint32_t* rescode, uint8_t* res, uint32_t* reslen) {
  std::vector<std::string> cmd;
  if (0 != parse_req(req, reqlen, cmd)) {
    std::cerr << "bad request." << std::endl;
    return -1;
  }
  if (cmd.size() == 2 && cmd_is(cmd[0], "get")) {
    *rescode = do_get(cmd, res, reslen);
  } else if (cmd.size() == 3 && cmd_is(cmd[0], "set")) {
    *rescode = do_set(cmd, res, reslen);
  } else if (cmd.size() == 2 && cmd_is(cmd[0], "del")) {
    *rescode = do_del(cmd, res, reslen);
  } else {
    *rescode = RES_ERR;
    const char* msg = "Unknow cmd";
    strcpy((char*)res, msg);
    *reslen = strlen(msg);
    return 0;
  }
  return 0;
}

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
  // printf("client say: %d, %s\n", len, &conn->rbuf[MSG_LEN_SIZE]);

  // got one request, generating echoing response
  uint32_t rescode = 0;
  uint32_t wlen = 0;
  int32_t err = do_request(&conn->rbuf[MSG_LEN_SIZE], len,
      &rescode, &conn->wbuf[MSG_LEN_SIZE + RESP_CODE_SIZE], &wlen);
  if (err) {
    conn->state = STATE_END;
    return false;
  }

  wlen += 4;
  memcpy(&conn->wbuf[0], &wlen, MSG_LEN_SIZE);
  memcpy(&conn->wbuf[MSG_LEN_SIZE], &rescode, 4);
  conn->wbuf_size = MSG_LEN_SIZE + wlen;

  // remove the request from the buffer.
  // note: frequent memmove is inefficient.
  // note need better handling for production code.
  size_t remain = conn->rbuf_size - 4 - len;
  if (remain) {
    memmove(conn->rbuf, &conn->rbuf[MSG_LEN_SIZE + len], remain);
  }
  conn->rbuf_size = remain;

  // change states
  conn->state = STATE_RES;
  state_res(conn);

  // continue the outer loop is the request was fully processed
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
      // normal finish
      // EOF
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
  return 0;
}
