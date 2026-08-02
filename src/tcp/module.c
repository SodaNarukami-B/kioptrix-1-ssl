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

#pragma pack(pop, 1)

//////// Initialization ////////

// That a mini functions, using just for optimization of code writing
uint16_t get_checksum(void *ptr, size_t count);
int _send(int sock, void *ptr, struct sockaddr_ll *sa);
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

  packet.ip.check = 0;

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

  // BUG: Packet not sended

  // DEV
};

// DEV
