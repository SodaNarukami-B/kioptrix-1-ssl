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

// XXX: Not used: {
int _send(int sock, void *ptr, size_t len, const struct sockaddr_ll *sa);
int _recv(int sock, void *buf, size_t buf_size);
// XXX: }

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

// XXX: to many arguments. Maybe we can make universal structure for addresses,
// because we calling ethhdr only with iphdr and tcp_conn, so why we don't make
// structure that contains all addresses that we needed

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
    fflush(stdout);
  };

  return _ack(sock, sa, eth, ip, tcp_conn);
};

int _syn(int sock, const struct sockaddr_ll *sa, const struct ethhdr *eth,
         const struct iphdr *ip, TCP_CONN *tcp_conn) {
  struct tcp_handshake_t packet;
  memset(&packet, 0, sizeof(struct tcp_handshake_t));

  /*
    XXX: Like a best practice you must use macroses for repeating structure
    data. Here's example:
    ``` C
    #define IP_HEADER_DEFAULT (struct iphdr) {\
      .version = 4,\
      .ihl = 5,\
      .ttl = 64,\
      // And etc.
    }
    ```

  */
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

  uint8_t checksum_buf[sizeof(struct pshdr) + sizeof(struct tcphdr)] = {
      0}; // XXX: Move sizes to constant fields or macroses

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

  uint8_t *ip_opts[40] = {0};
  int ip_opts_c = 0;

  if (parse_tcpip_fields(buf, recved, eth, ip, tcp_conn, (void *)ip_opts,
                         ip_opts_c) !=
      0) // BUG: passing value of variable (ip_opts_c). Pointer excepted.
    return -1;

  return 0;
};

int _ack(int sock, const struct sockaddr_ll *sa, const struct ethhdr *eth,
         const struct iphdr *ip, TCP_CONN *tcp_conn) {
  struct tcp_handshake_t packet;

  memset(&packet, 0, sizeof(struct tcp_handshake_t));

  memcpy(packet.eth.h_dest, eth->h_dest, 6);
  memcpy(packet.eth.h_source, eth->h_source, 6);
  packet.eth.h_proto = htons(ETH_P_IP);

  packet.ip.version = 4;
  packet.ip.ihl = sizeof(struct iphdr) / 4;
  packet.ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
  packet.ip.ttl = 64;
  packet.ip.protocol = IPPROTO_TCP;
  packet.ip.saddr = ip->saddr;
  packet.ip.daddr = ip->daddr;

  packet.ip.check = get_checksum(&packet.ip, sizeof(struct iphdr));

  packet.tcp.source = tcp_conn->source;
  packet.tcp.dest = tcp_conn->dest;
  tcp_conn->client_seq += 1;
  tcp_conn->serv_seq += 1;
  packet.tcp.seq = htonl(tcp_conn->client_seq);
  packet.tcp.ack_seq = htonl(tcp_conn->serv_seq);
  packet.tcp.doff = sizeof(struct tcphdr) / 4;
  packet.tcp.ack = 1;
  packet.tcp.window = 0xffff;

  uint8_t check_buf[sizeof(struct pshdr) + sizeof(struct tcphdr)] = {0};

  struct pshdr *ps = (struct pshdr *)check_buf;
  memcpy(check_buf + sizeof(struct pshdr), &packet.tcp, sizeof(struct tcphdr));

  ps->saddr = packet.ip.saddr;
  ps->daddr = packet.ip.daddr;
  ps->ipproto = packet.ip.protocol;
  ps->tcp_len = htons(sizeof(struct tcphdr));

  packet.tcp.check =
      get_checksum(check_buf, sizeof(struct tcphdr) + sizeof(struct pshdr));

  if (sendto(sock, &packet, sizeof(struct tcp_handshake_t), 0,
             (struct sockaddr *)sa, sizeof(struct sockaddr_ll)) < 0) {
    printf("[tcp/ERROR]: failed to send ack\n");
    return -1;
  };

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
