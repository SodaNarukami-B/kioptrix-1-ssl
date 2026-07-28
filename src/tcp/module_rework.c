#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "./module_ptr.h"

// NOTE: Rework plan
//
// What we need?
// - Splited archetecture
// - More steps of receiving
//
// Also i think about archetecture like this:
// int handshake() {
//   _syn();
//   _ack();
// };

// Realization

#pragma pack(push, 1)

// Main header structure (eth + ip + tcp)
struct tcp_pack_t {
  struct ethhdr eth;
  struct iphdr ip;
  struct tcphdr tcp;
};
// tcp_conn_t - structure for more comfortable passing handshake data between
// different functions
struct tcp_conn_t {
  uint16_t s_port;
  uint16_t d_port;
  uint32_t client_seq;
  uint32_t serv_seq;
};

#pragma pack(pop, 1)

int _syn(int sock, struct ethhdr *eth, struct iphdr *ip);
int _ack(int sock, struct ethhdr *eth, struct iphdr *ip);

int set_handshake(int sock, struct ethhdr *eth, struct iphdr *ip) {

  if (_syn(sock, eth, ip) < 0)
    return -1;

  _ack(sock, eth, ip);

  return 0;
};

// Here realization of child function
