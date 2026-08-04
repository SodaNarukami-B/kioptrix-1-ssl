// It's a third rework of tcp module
//
// What we need:
// We need a library with one function that setups a full tcp handshake
//
// Structure:
// I think I must do a splited structure and that mini-functions must be
// called in 1 main function of module. Like this:
// ```
// int _syn(int sock, ...);
// int _r_syn_ack(int sock, ...);
// int _ack(int sock, ...);
//
// int set_handshake(int sock, ...) {
//   _syn(int sock, ...);
//   _r_syn_ack(int sock, ...);
//   _ack(int sock, ...);
// }
// ```
// More details:
// I think we need to pass structures like [ethhdr] and [iphdr] as pointers
// to hard addresses and ip addresses and that structures must be filled in
// master file like configuration. Then we can use that example:
// >>> int _syn(int sock, struct ethhdr *eth, struct iphdr *ip, ...);
// That allows us to pass all needed data in 2-3 structures. And we can change
// data on pointers from _syn or other function.
// Also I think about structure that allows pass tcp connection info like ports,
// seq numbers and other useful data. So final base count of passing arguments
// (expect socket) is 3 - eth, ip and new structure named like tcp_conn
//
// Let's start!

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "./module_ptr.h"

//////// Structures ////////

#pragma pack(push, 1)

struct tcp_handshake_t {
  struct ethhdr eth;
  struct iphdr ip;
  struct tcphdr tcp;
};

struct pshdr {
  uint32_t saddr;
  uint32_t daddr;
  uint8_t zero;
  uint8_t ipproto;
  uint16_t tcp_len;
};

#pragma pack(pop)

//////// Initialization ////////

// That a mini functions, using just for optimization of code writing
uint16_t get_checksum(void *ptr, size_t count);
int _send(int sock, void *ptr, size_t len, const struct sockaddr_ll *sa);
int _recv(int sock, void *buf, size_t buf_size);

// That a modules for tcp handshake

// Syncronize - first step of tcp handshake
int _syn(int sock, const struct sockaddr_ll *sa, const struct ethhdr *eth,
         const struct iphdr *ip, TCP_CONN *tcp_conn);

// Function for receive and parse resporse on our packet sended in syncronize
// step
int _r_syn_ack(int sock, void *buf, size_t buf_size, const struct ethhdr *eth,
               const struct iphdr *ip, TCP_CONN *tcp_conn);

// Ack - Third step of tcp handshake
int _ack(int sock, const struct sockaddr_ll *sa, const struct ethhdr *eth,
         const struct iphdr *ip, TCP_CONN *tcp_conn);

// Main function
int set_handshake(int sock, const struct sockaddr_ll *sa,
                  const struct ethhdr *eth, const struct iphdr *ip,
                  TCP_CONN *tcp_conn);

//////// Realization ////////

int set_handshake(int sock, const struct sockaddr_ll *sa,
                  const struct ethhdr *eth, const struct iphdr *ip,
                  TCP_CONN *tcp_conn) {
  printf("[tcp/INFO]: setting tcp handshake\n");

  uint8_t buffer[1024] = {0};

  // Steps
  if (_syn(sock, sa, eth, ip, tcp_conn) < 0) {
    return -1;
  };

  printf("[tcp/INFO]: waiting for syn ack (0)");
  fflush(stdout);

  int counter = 0;

  while (1) {
    counter++;

    if (_r_syn_ack(sock, buffer, 1024, eth, ip, tcp_conn) == 0) {
      printf("\n");
      printf("[tcp/INFO]: syn-ack received\n");
      break;
    };

    printf("\r[tcp/INFO]: waiting for syn ack (%d)", counter);
  };

  return 0;
};

int _syn(int sock, const struct sockaddr_ll *sa, const struct ethhdr *eth,
         const struct iphdr *ip, TCP_CONN *tcp_conn) {
  struct tcp_handshake_t packet;
  memset(&packet, 0, sizeof(struct tcp_handshake_t));

  // Ethhdr
  memcpy(&packet.eth.h_dest, eth->h_dest, 6);
  memcpy(&packet.eth.h_source, eth->h_source, 6);
  packet.eth.h_proto = htons(ETH_P_IP);

  // Iphdr
  uint16_t ip_tcp_len = sizeof(struct iphdr) + sizeof(struct tcphdr);

  packet.ip.version = 4;
  packet.ip.ihl = sizeof(struct iphdr) / 4;
  packet.ip.tot_len = htons(ip_tcp_len);
  packet.ip.ttl = 64;
  packet.ip.protocol = IPPROTO_TCP;
  packet.ip.check = 0;
  packet.ip.saddr = ip->saddr;
  packet.ip.daddr = ip->daddr;

  packet.ip.check = get_checksum(&packet.ip, sizeof(struct iphdr));

  // Tcp
  packet.tcp.source = tcp_conn->source;
  packet.tcp.dest = tcp_conn->dest;
  packet.tcp.seq = htonl(tcp_conn->client_seq);
  packet.tcp.doff = sizeof(struct tcphdr) / 4;
  packet.tcp.syn = 1;
  packet.tcp.window = 0xffff;
  packet.tcp.check = 0;

  uint8_t checksum_buf[sizeof(struct pshdr) + sizeof(struct tcphdr)] = {0};

  struct pshdr *ps = (struct pshdr *)checksum_buf;

  memcpy(checksum_buf + sizeof(struct pshdr), &packet.tcp,
         sizeof(struct tcphdr));

  ps->saddr = ip->saddr;
  ps->daddr = ip->daddr;
  ps->ipproto = IPPROTO_TCP;
  ps->tcp_len = htons(sizeof(struct tcphdr));

  packet.tcp.check = get_checksum(checksum_buf, sizeof(checksum_buf));

  int sended = sendto(sock, &packet, sizeof(struct tcp_handshake_t), 0,
                      (const struct sockaddr *)sa, sizeof(struct sockaddr_ll));

  if (sended <= 0) {
    printf("[tcp/ERROR]: failed to send syncronize\n");
  };

  printf("[tcp/INFO]: syncronize sended\n");

  return 0;
};

int _r_syn_ack(int sock, void *buf, size_t buf_size, const struct ethhdr *eth,
               const struct iphdr *ip, TCP_CONN *tcp_conn) {
  int recved = recvfrom(sock, buf, buf_size, 0, NULL, NULL);

  if (recved < 0) {
    printf("[tcp/ERROR]: connection timeout\n");
    return -1;
  };

  if (recved == 0) {
    printf("[tcp/ERROR]: connection closed by remote host\n");
    return -1;
  };

  // BUG: Casting cosntant structure to dynamic data. Here's can be additional
  //      options for ip header that doesn't existis in casting structure
  //
  // TIP: You need to parse fields depending on size-fields like IHL and Data
  //      Offset. Also you can use down code as TODO list what needed to be
  //
  // PS: Checksum validating also needed but im not a nerd bruh.

  struct tcp_handshake_t *recv_pack = (struct tcp_handshake_t *)buf;
  // eth
  if (ntohs(recv_pack->eth.h_proto) != ETH_P_IP)
    return -1;

  if (memcmp(recv_pack->eth.h_source, eth->h_dest, 6) != 0)
    return -1;

  if (memcmp(recv_pack->eth.h_dest, eth->h_source, 6) != 0)
    return -1;

  // ip
  if (recv_pack->ip.version != 4)
    return -1;

  if (recv_pack->ip.protocol != IPPROTO_TCP)
    return -1;

  if (recv_pack->ip.saddr != ip->daddr)
    return -1;

  if (recv_pack->ip.daddr != ip->saddr)
    return -1;

  // tcp
  if (recv_pack->tcp.source != tcp_conn->dest)
    return -1;

  if (recv_pack->tcp.dest != tcp_conn->source)
    return -1;

  if (ntohl(recv_pack->tcp.ack_seq) != (tcp_conn->client_seq + 1))
    return -1;

  tcp_conn->serv_seq = ntohl(recv_pack->tcp.seq);

  if (!(recv_pack->tcp.syn && recv_pack->tcp.ack) || recv_pack->tcp.fin)
    return -1;

  return 0;
};

uint16_t get_checksum(void *ptr, size_t count) {
  uint16_t *p = (uint16_t *)ptr;

  uint32_t result = 0;

  while (count > 1) {
    result += *p++;
    count -= 2;
  };

  if (count > 0) {
    result += *(uint8_t *)p;
  };

  while (result >> 16) {
    result = (result & 0xffff) + (result >> 16);
  };

  return (uint16_t)(~result);
};

// DEV
