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
  (struct iphdr) { .version = 4, .ihl = 5, .ttl = 64, .protocol = IPPROTO_TCP, }

#define TCP_HDR_DEFAULT                                                        \
  (struct tcphdr){                                                             \
      .doff = 5,                                                               \
      .window = 0xffff,                                                        \
  };

// -----------------------------------------------------------------------------

#pragma pack(push, 1)

struct packet_t {
  struct ethhdr eth;
  struct iphdr ip;
  struct tcphdr tcp;
};

struct tcp_check_struct {
  uint32_t source;
  uint32_t dest;
  uint8_t zero;
  uint8_t protocol;
  uint16_t tcp_len;
  struct tcphdr tcp;
};

#pragma pack(pop)

// Initalization

uint16_t get_check(const void *ptr, size_t s);

static int _syn(int sock, const struct sockaddr_ll *sa,
                const endpoint_addr_t *ep, tcp_conn_t *conn);

static int _r_syn_ack(int sock, void *buf, size_t bs,
                      const struct endpoint_hdr *ep, tcp_conn_t *conn);

static int _ack(int sock, struct sockaddr_ll *sa, const endpoint_addr_t *ep,
                tcp_conn_t *conn);

int set_handshake(int sock, const struct sockaddr_ll *sa,
                  const endpoint_addr_t *ep, tcp_conn_t *conn);

// ------------------------------------------------------------------------------

// Realization

int set_handshake(int sock, const struct sockaddr_ll *sa,
                  const endpoint_addr_t *ep, tcp_conn_t *conn) {
  if (_syn(sock, sa, ep, conn) < 0) {
    return -1;
  };

  // ...
  return 0;
};

static int _syn(int sock, const struct sockaddr_ll *sa,
                const endpoint_addr_t *ep, tcp_conn_t *conn) {
  struct packet_t pack;
  memset(&pack, 0, sizeof(struct packet_t));

  // Defaults
  pack.ip = IP_HDR_DEFAULT;
  pack.tcp = TCP_HDR_DEFAULT;

  // Eth
  memcpy(pack.eth.h_source, ep->h_source, 6);
  memcpy(pack.eth.h_dest, ep->h_dest, 6);
  pack.eth.h_proto = htons(ETH_P_IP);

  // Ip
  pack.ip.tot_len = htons(sizeof(struct tcphdr) + sizeof(struct iphdr));
  pack.ip.saddr = ep->source;
  pack.ip.daddr = ep->dest;
  pack.ip.check = get_check(&pack.ip, sizeof(struct iphdr));

  // Tcp
  pack.tcp.source = conn->source;
  pack.tcp.dest = conn->dest;
  pack.tcp.seq = htonl(conn->client_seq);
  pack.tcp.syn = 1;

  struct tcp_check_struct check_var;

  check_var.tcp = pack.tcp;
  check_var.source = ep->source;
  check_var.dest = ep->dest;
  check_var.protocol = IPPROTO_TCP;
  check_var.tcp_len = htons(sizeof(struct tcphdr));

  pack.tcp.check = get_check(&check_var, sizeof(struct tcp_check_struct));

  int sended = sendto(sock, &pack, sizeof(struct packet_t), 0,
                      (struct sockaddr *)sa, sizeof(struct sockaddr_ll));

  if (sended <= 0) {
    printf("[tcph/ERROR]: Failed to send syn-packet\n");
    return -1;
  };

  return 0;
};

static int _r_syn_ack(int sock, void *buf, size_t bs,
                      const struct endpoint_hdr *ep, tcp_conn_t *conn) {
  // ...
  return 0;
};

static int _ack(int sock, struct sockaddr_ll *sa, const endpoint_addr_t *ep,
                tcp_conn_t *conn) {
  // ...
  return 0;
};

uint16_t get_check(const void *ptr, size_t s) {
  const uint16_t *p = (const uint16_t *)ptr;

  uint32_t result = 0;

  while (s > 1) {
    result += *p++;
    s -= 2;
  };

  if (s > 0) {
    result += *(uint8_t *)p;
    s--;
  };

  while (result >> 16) {
    result = (result & 0xffff) + (result >> 16);
  };

  return (uint16_t)(~result);
};
