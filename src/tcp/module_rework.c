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
// - Splited archetecture    *
// - More steps of receiving -
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

#pragma pack(pop, 1)

// NOTE: Initialization / callable talbe
int _syn(int sock, struct ethhdr *eth, struct iphdr *ip,
         struct tcp_conn_t *tcp);
int _ack(int sock, struct ethhdr *eth, struct iphdr *ip,
         struct tcp_conn_t *tcp);
int set_handshake(int sock, struct ethhdr *eth, struct iphdr *ip,
                  struct tcp_conn_t *tcp);
uint16_t get_checksum(void *ptr, size_t len);

// NOTE: Realization
int set_handshake(int sock, struct ethhdr *eth, struct iphdr *ip,
                  struct tcp_conn_t *tcp_conn) {

  if (_syn(sock, eth, ip, tcp_conn) < 0)
    return -1;

  _ack(sock, eth, ip, tcp_conn);

  return 0;
};

// NOTE: Realization / child functions

int _syn(int sock, struct ethhdr *eth, struct iphdr *ip,
         struct tcp_conn_t *tcp_conn) {
  struct tcp_pack_t pack;
  memset(&pack, 0, sizeof(struct tcp_pack_t));

  // ethhdr
  memcpy(pack.eth.h_dest, eth->h_dest, 6);
  memcpy(pack.eth.h_source, eth->h_source, 6);
  pack.eth.h_proto = htons(ETH_P_IP);

  // iphdr
  uint16_t tcp_ip_len =
      htons(sizeof(struct tcp_pack_t) - sizeof(struct ethhdr));

  pack.ip.version = 4;
  pack.ip.ihl = sizeof(struct iphdr) / 4;
  pack.ip.tot_len = tcp_ip_len;
  pack.ip.ttl = 64;
  pack.ip.protocol = IPPROTO_TCP;
  // For correctly checksum calculating, we setting zero checksum before
  // calculating
  pack.ip.check = 0;
  // Copying addresses
  memcpy((uint8_t *)&pack.ip.saddr, (uint8_t *)&ip->saddr, 4);
  memcpy((uint8_t *)&pack.ip.daddr, (uint8_t *)&ip->daddr, 4);

  // tcphdr
  pack.tcp.source = htons(tcp_conn->s_port);
  pack.tcp.dest = htons(tcp_conn->d_port);
  pack.tcp.seq = htonl(tcp_conn->client_seq);
  /*
    uint8_t data_offset =
        ((uint8_t *)(&pack.tcp.urg_ptr + 1) - (uint8_t *)(&pack.tcp)) / 4;
                    ^^^^^^^^^^^^^^^^^^^^^^^
    TIP: You can use that method when there is external options or non-zero
    payload
  */
  pack.tcp.doff = sizeof(struct tcphdr) / 4;
  pack.tcp.syn = 1;
  pack.tcp.window = 0xffff;
  pack.tcp.check = 0; // Same like in iphdr

  // sending
  // ...
};
