#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "./module_ptr.h"

// ----------------------------------------------------------------------------
#define MIN_CHECK_TCP_BUF 32 // XXX: Maybe not needed idk

#define IP_HDR_DEFAULT                                                                                                                     \
  (struct iphdr) { .version = 4, .ihl = 5, .ttl = 64, .protocol = IPPROTO_TCP, }

#define TCP_HDR_DEFAULT                                                                                                                    \
  (struct tcphdr){                                                                                                                         \
      .doff = 5,                                                                                                                           \
      .window = 0xffff,                                                                                                                    \
  };

// -----------------------------------------------------------------------------

#pragma pack(push, 1)

struct tcpip {
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

// -------------------

struct sslhdr {
  uint16_t msb : 1;
  uint16_t rec_len;
  uint8_t msg_type;
  uint16_t source_ver;
  uint16_t chiphers_count;
  uint16_t session_id_len;
  uint16_t challenge_len;
  // Chipher specs (dynamic)
  // Challenge data (dynamic)
};

struct ssl_packet {
  struct tcpip tcpip;
  struct sslhdr ssl;
};

#pragma pack(pop)

// Initalization

uint16_t get_check(const void *ptr, size_t s);

// Tcp
static int _syn(int sock, const struct sockaddr_ll *sa, const endpoint_addr_t *ep, tcp_conn_t *conn);

static int _r_syn_ack(int sock, const struct endpoint_hdr *ep, tcp_conn_t *conn, uint8_t th_flags);

static int _ack(int sock, const struct sockaddr_ll *sa, const endpoint_addr_t *ep, tcp_conn_t *conn);

int set_handshake(int sock, const struct sockaddr_ll *sa, const endpoint_addr_t *ep, tcp_conn_t *conn);

// Ssl

int set_ssl_connect(int sock, const struct sockaddr_ll *sa, const endpoint_addr_t *ep, tcp_conn_t *conn);

static int _ssl_c_hello(int sock, const struct sockaddr_ll *sa, const endpoint_addr_t *ep, tcp_conn_t *conn);

// ------------------------------------------------------------------------------

// Realization

int set_handshake(int sock, const struct sockaddr_ll *sa, const endpoint_addr_t *ep, tcp_conn_t *conn) {
  // -----------------------------------------------------------

  if (_syn(sock, sa, ep, conn) < 0) {
    return -1;
  };

  // -----------------------------------------------------------

  struct endpoint_hdr ep_hdr;

  ep_hdr.eth.h_proto = htons(ETH_P_IP);
  memcpy(ep_hdr.eth.h_source, ep->h_source, 6);
  memcpy(ep_hdr.eth.h_dest, ep->h_dest, 6);

  ep_hdr.ip = IP_HDR_DEFAULT;
  // Check not needed
  ep_hdr.ip.saddr = ep->source;
  ep_hdr.ip.daddr = ep->dest;

  ep_hdr.conn = *conn;

  const uint8_t expected_answer = SYN_ACK;

  _r_syn_ack(sock, &ep_hdr, conn, expected_answer);

  // -----------------------------------------------------------

  if (_ack(sock, sa, ep, conn) < 0) {
    return -1;
  };

  return 0;
};

int set_ssl_connect(int sock, const struct sockaddr_ll *sa, const endpoint_addr_t *ep, tcp_conn_t *conn) {
  if (_ssl_c_hello(sock, sa, ep, conn) < 0) {
    return -1;
  };

  return 0;
};

static int _syn(int sock, const struct sockaddr_ll *sa, const endpoint_addr_t *ep, tcp_conn_t *conn) {
  struct tcpip pack;
  memset(&pack, 0, sizeof(struct tcpip));

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

  struct tcp_check_struct check_var = {0};

  check_var.source = ep->source;
  check_var.dest = ep->dest;
  check_var.protocol = IPPROTO_TCP;
  check_var.tcp_len = htons(sizeof(struct tcphdr));
  check_var.tcp = pack.tcp;

  pack.tcp.check = get_check(&check_var, sizeof(struct tcp_check_struct));

  // Sending
  int sended = sendto(sock, &pack, sizeof(struct tcpip), 0, (struct sockaddr *)sa, sizeof(struct sockaddr_ll));

  if (sended <= 0) {
    printf("[tcph/ERROR]: Failed to send syn-packet\n");
    return -1;
  };

  return 0;
};

static int _r_syn_ack(int sock, const struct endpoint_hdr *ep, tcp_conn_t *conn, uint8_t th_flags) {
  uint8_t recv_buf[128] = {0};

  /* int count = 0; */

  /* printf("[tcph/DEBUG]: wating for syn-ack (0)\r"); */
  fflush(stdout);

  while (1) {
    /* count++; */
    /* printf("[tcph/DEBUG]: waiting for syn-ack(%d)\r", count); */
    fflush(stdout);

    int recved = recvfrom(sock, recv_buf, 128, 0, NULL, NULL);

    if (recved <= 0)
      continue;

    if (parse_tcpip(recv_buf, recved, ep, conn, th_flags) == 0) {
      /* printf("\n[tcph/DEBUG]: syn-ack received\n"); */
      break;
    };
  };

  return 0;
};

static int _ack(int sock, const struct sockaddr_ll *sa, const endpoint_addr_t *ep, tcp_conn_t *conn) {
  struct tcpip pack;

  memcpy(pack.eth.h_source, ep->h_source, 6);
  memcpy(pack.eth.h_dest, ep->h_dest, 6);
  pack.eth.h_proto = htons(ETH_P_IP);

  pack.ip = IP_HDR_DEFAULT;
  pack.tcp = TCP_HDR_DEFAULT;

  pack.ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
  pack.ip.saddr = ep->source;
  pack.ip.daddr = ep->dest;
  pack.ip.check = get_check(&pack.ip, sizeof(struct iphdr));

  pack.tcp.source = conn->source;
  pack.tcp.dest = conn->dest;
  pack.tcp.seq = htonl(conn->client_seq++);
  pack.tcp.ack_seq = htonl(conn->serv_seq++);
  pack.tcp.ack = 1;

  struct tcp_check_struct check_var = {0};

  check_var.source = pack.ip.saddr;
  check_var.dest = pack.ip.daddr;
  check_var.protocol = pack.ip.protocol;
  check_var.tcp_len = sizeof(struct tcphdr);

  check_var.tcp = pack.tcp;

  pack.tcp.check = get_check(&check_var, sizeof(struct tcp_check_struct));

  int sended = sendto(sock, &pack, sizeof(struct tcpip), 0, (struct sockaddr *)sa, sizeof(struct sockaddr_ll));

  if (sended <= 0) {
    printf("[tcph/ERROR]: failed to send ack\n");
    return -1;
  }

  return 0;
};

static int _ssl_c_hello(int sock, const struct sockaddr_ll *sa, const endpoint_addr_t *ep, tcp_conn_t *conn) {

  struct ssl_packet pack = {0};

  // Defaults
  pack.tcpip.ip = IP_HDR_DEFAULT;
  pack.tcpip.tcp = TCP_HDR_DEFAULT;

  // Eth
  memcpy(pack.tcpip.eth.h_dest, ep->h_dest, 6);
  memcpy(pack.tcpip.eth.h_source, ep->h_source, 6);
  pack.tcpip.eth.h_proto = htons(ETH_P_IP);

  // Ip
  pack.tcpip.ip.tot_len = sizeof(struct ssl_packet);
  pack.tcpip.ip.saddr = ep->source;
  pack.tcpip.ip.daddr = ep->dest;
  pack.tcpip.ip.check = get_check(&pack.tcpip.ip, sizeof(struct iphdr));

  // Tcp
  pack.tcpip.tcp.source = conn->source;
  pack.tcpip.tcp.dest = conn->dest;
  pack.tcpip.tcp.seq = htonl(conn->client_seq + 1);
  pack.tcpip.tcp.ack_seq = htonl(conn->serv_seq);
  pack.tcpip.tcp.ack = 1;

  struct tcp_check_struct check = {0};

  check.tcp = pack.tcpip.tcp;

  check.source = pack.tcpip.ip.saddr;
  check.dest = pack.tcpip.ip.daddr;
  check.protocol = htons(IPPROTO_TCP);
  check.tcp_len = htons(sizeof(struct tcphdr) + sizeof(struct sslhdr) + 19);

  pack.tcpip.tcp.check = get_check(&check, sizeof(struct tcp_check_struct));

  // Ssl
  pack.ssl.msb = 1;
  pack.ssl.rec_len = sizeof(struct sslhdr);
  pack.ssl.msg_type = 1;
  pack.ssl.source_ver = htons(0x0200);
  pack.ssl.chiphers_count = htons(1);
  pack.ssl.challenge_len = htons(3); // 1 chipher
  pack.ssl.challenge_len = htons(16);

  uint8_t *buffer = (uint8_t *)calloc(1, sizeof(struct ssl_packet) + 19);
  memcpy(buffer, &pack, sizeof(struct ssl_packet));

  uint8_t payload[19] = {
      0x01, 0x00, 0x80,                                                                              // Chipher
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00 // Challenge
  };

  memcpy(buffer + sizeof(struct ssl_packet), payload, 19);

  int sended = sendto(sock, buffer, sizeof(struct ssl_packet) + 19, 0, (struct sockaddr *)&sa, sizeof(struct sockaddr_ll));

  if (sended < 0) {
    printf("[ssl/ERROR]: failed to send client hello\n");
    return -1;
  };

  printf("[ssl/INFO]: client hello sended\n");
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

/* EOF */
