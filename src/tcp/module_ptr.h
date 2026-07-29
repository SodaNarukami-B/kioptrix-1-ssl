#ifndef TCP
#define TCP

#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <stdint.h>

#pragma pack(push, 1)

// tcp_conn_t - structure for more comfortable passing handshake data between
// different functions
struct tcp_conn_t {
  uint16_t s_port;
  uint16_t d_port;
  uint32_t client_seq;
  uint32_t serv_seq;
};

#pragma pack(pop)

int set_handshake(int sock, struct ethhdr *eth, struct iphdr *ip,
                  struct tcp_conn_t *tcp_conn, struct sockaddr_ll *sa);

#endif
