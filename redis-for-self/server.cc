#include <cassert>
#include <iostream>
#include <vector>
#include <map>

#include <stdio.h>
#include <strings.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>

#include "hashtable.h"
#include "zset.h"
#include "common.h"

static void msg(const char* msg) {
  fprintf(stderr, "%s\n", msg);
}

static void die(const char* msg) {
  int err = errno;
  fprintf(stderr, "[%d] %s\n", msg);
  abort();
}

static void fd_set_nb(int fd) {
  errno = 0;
  int flags = fcntl(fd, F_GETFL, 0);
  if (errno) {
    die("fcntl error");
    return;
  }
  flags |= O_NONBLOCK;

  errno = 0;
  (void)fcntl(fd, F_SETFL, flags);
  if (errno) {
    die("fcntl error");
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

// the data structure for the key space
static struct {
  HMap db;
} g_data;

enum {
  T_STR = 0,
  T_ZSET = 1,
};

// the structure from the key
struct Entry {
  struct HNode node;
  std::string key;
  std::string val;
  uint32_t type = 0;
  ZSet* zset = NULL;
};

static bool entry_eq(HNode* lhs, HNode* rhs) {
  struct Entry* le = container_of(lhs, struct Entry, node);
  struct Entry* re = container_of(rhs, struct Entry, node);
  return lhs->hcode == rhs->hcode && le->key == re->key;
}

enum {
  ERR_UNKNOWN = 1,
  ERR_2BIG = 2,
  ERR_TYPE = 3,
  ERR_ARG = 4,
};

static void out_nil(std::string& out) {
  out.push_back(SER_NIL);
}

static void out_str(std::string& out, const char* s, size_t size) {
  out.push_back(SER_STR);
  uint32_t len = (uint32_t)size;
  out.append((char*)&len, 4);
  out.append(s, len);
}

static void out_str(std::string& out, const std::string& val) {
  out.push_back(SER_STR);
  uint32_t len = (uint32_t)val.size();
  out.append((char*)&len, 4);
  out.append(val);
}

static void out_int(std::string& out, int64_t val) {
  out.push_back(SER_INT);
  out.append((char*)&val, 8);
}

static void out_dbl(std::string& out, double val) {
  out.push_back(SER_DBL);
  out.append((char*)&val, 8);
}

static void out_err(std::string& out, int32_t code, const std::string& msg) {
  out.push_back(SER_ERR);
  out.append((char*)&code, 4);
  uint32_t len = (uint32_t)msg.size();
  out.append((char*)&len, 4);
  out.append(msg);
}

static void out_arr(std::string& out, uint32_t n) {
  out.push_back(SER_ARR);
  out.append((char*)&n, 4);
}

static void* begin_arr(std::string& out) {
  out.push_back(SER_ARR);
  out.append("\0\0\0\0", 4);    // filled in end_arr()
  return (void*)(out.size() - 4);   // the `ctx` arg
}

static void end_arr(std::string& out, void* ctx, uint32_t n) {
  size_t pos = (size_t)ctx;
  assert(out[pos - 1] == SER_ARR);
  memcpy(&out[pos], &n, 4);
}

static void do_get(std::vector<std::string>& cmd, std::string& out) {
  Entry key;
  key.key.swap(cmd[1]);
  key.node.hcode = str_hash((uint8_t*)key.key.data(), key.key.size());

  HNode* node = hm_lookup(&g_data.db, &key.node, &entry_eq);
  if (!node) {
    return out_nil(out);
  }
  const std::string& val = container_of(node, Entry, node)->val;
  out_str(out, val);
}

static void do_set(std::vector<std::string>& cmd, std::string& out) {
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
  return out_nil(out);
}

static void entry_del(Entry* ent) {
  switch(ent->type) {
    case T_ZSET:
      zset_dispose(ent->zset);
      delete ent->zset;
      break;
  }
  delete ent;
}

static void do_del(std::vector<std::string>& cmd, std::string& out) {
  Entry key;
  key.key.swap(cmd[1]);
  key.node.hcode = str_hash((uint8_t*)key.key.data(), key.key.size());

  HNode* node = hm_pop(&g_data.db, &key.node, &entry_eq);
  if (node) {
    entry_del(container_of(node, Entry, node));
  }
  return out_int(out, node ? 1 : 0);
}

static void h_scan(HTab* tab, void(*f)(HNode*, void*), void* arg) {
  if (tab->size == 0) {
    return ;
  }
  for (size_t i = 0; i < tab->mask+1; ++i) {
    HNode* node = tab->tab[i];
    while (node) {
      f(node, arg);
      node = node->next;
    }
  }
}

static void cb_scan(HNode* node, void* arg) {
  std::string& out = *(std::string*)arg;
  out_str(out, container_of(node, Entry, node)->key);
}

static void do_keys(std::vector<std::string>& cmd, std::string& out) {
  (void)cmd;
  out_arr(out, (uint32_t)hm_size(&g_data.db));
  h_scan(&g_data.db.ht1, &cb_scan, &out);
  h_scan(&g_data.db.ht2, &cb_scan, &out);
}

static bool str2dbl(const std::string& s, double& out) {
  char* endp = NULL;
  out = strtod(s.c_str(), &endp);
  return endp == s.c_str() + s.size() && !isnan(out);
}

static bool str2int(const std::string& s, int64_t& out) {
  char* endp = NULL;
  out = strtoll(s.c_str(), &endp, 10);
  return endp == s.c_str() + s.size();
}

static void do_zadd(std::vector<std::string>& cmd, std::string& out) {
  double score = 0;
  if (!str2dbl(cmd[2], score)) {
    return out_err(out, ERR_ARG, "expect fp number");
  }

  // look up or create the zset
  Entry key;
  key.key.swap(cmd[1]);
  key.node.hcode = str_hash((uint8_t*)key.key.data(), key.key.size());
  HNode* hnode = hm_lookup(&g_data.db, &key.node, &entry_eq);

  Entry* ent = NULL;
  if(!hnode) {
    ent = new Entry();
    ent->key.swap(key.key);
    ent->node.hcode = key.node.hcode;
    ent->type = T_ZSET();
    hm_insert(&g_data.db, &ent->node);
  } else {
    ent = container_of(hnode, Entry, node);
    if (ent->type != T_ZSET) {
      return out_err(out, ERR_TYPE, "expect zset");
    }
  }

  // add or update the tuple
  const std::string& name = cmd[3];
  bool added = zset_add(ent->zset, name.data(), name.size(), score);
  return out_int(out, (int64_t)added);
}

static bool expect_zset(std::string& out, std::string& s, Entry** ent) {
  Entry key;
  key.key.swap(s);
  key.node.hcode = str_hash((uint8_t*)key.key.data(), key.key.size());
  HNode* hnode = hm_lookup(&g_data.db, &key.node, &entry_eq);
  if (!hnode) {
    out_nil(out);
    return false;
  }

  *ent = container_of(hnode, Entry, node);
  if ((*ent)->type != T_ZSET) {
    out_err(out, ERR_TYPE, "expect zset");
    return false;
  }
  return true;
}

// zrem zset name
static void do_zrem(std::vector<std::string>& cmd, std::string& out) {
  Entry* ent = NULL;
  if (!expect_zset(out, cmd[1], &ent)) {
    return;
  }

  const std::string& name = cmd[2];
  ZNode* znode = zset_pop(ent->zset, name.data(), name.size());
  if (znode) {
    znode_del(znode);
  }
  return out_int(out, znode ? 1 : 0);
}

// zscore zet name
static void do_zscore(std::vector<std::string>& cmd, std::string& out) {
  Entry* ent = NULL;
  if (!expect_zset(out, cmd[1], &ent)) {
    return;
  }

  const std::string& name = cmd[2];
  ZNode* znode = zset_lookup(ent->zset, name.data(), name.size());
  return znode ? out_dbl(out, znode->score) : out_nil(out);
}

// zquery zset score name offset limit
static void do_zquery(std::vector<std::string>& cmd, std::string& out) {
  // parse args
  double score = 0;
  if (!str2dbl(cmd[2], score)) {
    return out_err(out, ERR_ARG, "expect fp number");
  }
  const std::string& name = cmd[3];
  int64_t offset = 0;
  int64_t limit = 0;
  if (!str2int(cmd[4], offset)) {
    return out_err(out, ERR_ARG, "expect int");
  }
  if (!str2int(cmd[5], limit)) {
    return out_err(out, ERR_ARG, "expect int");
  }

  // get the zset
  Entry* ent = NULL;
  if (!expect_zset(out, cmd[1], &ent)) {
    if (out[0] == SER_NIL) {
      out.clear();
      out_arr(out, 0);
    }
    return ;
  }

  // look up the tuple
  if (limit <= 0) {
    return out_arr(out, 0);
  }
  ZNode* znode = zset_query(ent->zset, score, name.data(), name.size());
  znode = znode_offset(znode, offset);

  // output
  void* arr = begin_arr(out);
  uint32_t n = 0;
  while(znode && (int64_t)n < limit) {
    out_str(out, znode->name, znode->len);
    out_dbl(out, znode->score);
    znode = znode_offset(znode, +1);
    n += 2;
  }
  end_arr(out, arr, n);
}

static bool cmd_is(const std::string& in, const std::string& cmd) {
  return (in == cmd);
}

static void do_request(std::vector<std::string>& cmd, std::string& out) {
  if (cmd.size() == 1 && cmd_is(cmd[0], "keys")) {
    do_keys(cmd, out);
  } else if (cmd.size() == 2 && cmd_is(cmd[0], "get")) {
    do_get(cmd, out);
  } else if (cmd.size() == 3 && cmd_is(cmd[0], "set")) {
    do_set(cmd, out);
  } else if (cmd.size() == 2 && cmd_is(cmd[0], "del")) {
    do_del(cmd, out);
  } else if(cmd.size() == 4 && cmd_is(cmd[0], "zadd")) {
    do_zadd(cmd, out);
  } else if (cmd.size() == 3 && cmd_is(cmd[0], "zrem")) {
    do_zrem(cmd, out);
  } else if (cmd.size() == 3 && cmd_is(cmd[0], "zscore")) {
    do_zscore(cmd, out);
  } else if (cmd.size() == 6 && cmd_is(cmd[0], "zquery")) {
    do_zquery(cmd, out);
  } else {
    // cmd is not recognized
    out_err(out, ERR_UNKNOWN, "Unknow cmd");
  }
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

  // parse the request
  std::vector<std::string> cmd;
  if (0 != parse_req(&conn->rbuf[4], len, cmd)) {
    std::cerr << "bad request." << std::endl;
    conn->state = STATE_END;
    return false;
  }

  // got one request, generating the response
  std::string out;
  do_request(cmd, out);

  // pack the response into the buffer
  if (4 + out.size() > MAX_MSG_LEN) {
    out.clear();
    out_err(out, ERR_2BIG, "response is too big");
  }

  uint32_t wlen = (uint32_t)out.size();
  memcpy(&conn->wbuf[0], &wlen, MSG_LEN_SIZE);
  memcpy(&conn->wbuf[MSG_LEN_SIZE], out.data(), out.size());
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
