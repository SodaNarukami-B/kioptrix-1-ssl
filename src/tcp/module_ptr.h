#ifndef TCP
#define TCP

#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <stdint.h>

#pragma pack(push, 1)

// tcp_conn_t - structure for more comfortable passing handshake data between
// different functions
typedef struct {
  uint16_t source;
  uint16_t dest;
  uint32_t client_seq;
  uint32_t serv_seq;
} TCP_CONN;

#pragma pack(pop)

int set_handshake(int sock, const struct sockaddr_ll *sa,
                  const struct ethhdr *eth, const struct iphdr *ip,
                  TCP_CONN *tcp_conn);
#endif
