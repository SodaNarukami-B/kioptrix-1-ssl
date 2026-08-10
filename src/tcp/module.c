#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "./module_ptr.h"

// ----------------------------------------------------------------------------
#define MIN_CHECK_TCP_BUF 32; // XXX: Maybe not needed idk

#define IP_HDR_DEFAULT                                                         \
  (struct iphdr) {                                                             \
    .version = 4, .ihl = 5, .tot_len = 20, .ttl = 64, .protocol = IPPROTO_TCP, \
  }

#define TCP_HDR_DEFAULT                                                        \
  (struct tcphdr){                                                             \
      .doff = 5,                                                               \
      .window = 0xffff,                                                        \
  };

// -----------------------------------------------------------------------------

// Initalization

uint16_t get_checksum(const void *ptr, size_t s);

int _syn(int sock, const struct sockaddr_ll *sa, const endpoint_addr_t *ep,
         tcp_conn_t *conn);

int _r_syn_ack(int sock, void *buf, size_t bs, const struct endpoint_hdr *ep,
               tcp_conn_t *conn);

int _ack(int sock, struct sockaddr_ll *sa, const endpoint_addr_t *ep,
         tcp_conn_t *conn);

int set_handshake(int sock, const struct sockaddr_ll *sa,
                  const endpoint_addr_t *ep, tcp_conn_t *conn);

// ------------------------------------------------------------------------------

// Realization

int set_handshake(int sock, const struct sockaddr_ll *sa,
                  const endpoint_addr_t *ep, tcp_conn_t *conn) {
  // ...
  return 0;
};

int _syn(int sock, const struct sockaddr_ll *sa, const endpoint_addr_t *ep,
         tcp_conn_t *conn) {
  // ...
  return 0;
};

int _r_syn_ack(int sock, void *buf, size_t bs, const struct endpoint_hdr *ep,
               tcp_conn_t *conn) {
  // ...
  return 0;
};

int _ack(int sock, struct sockaddr_ll *sa, const endpoint_addr_t *ep,
         tcp_conn_t *conn) {
  // ...
  return 0;
};

uint16_t get_checksum(const void *ptr, size_t s) {
  // ...
  return (uint16_t)(~0);
};
