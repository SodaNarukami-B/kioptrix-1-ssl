#ifndef TCP
#define TCP

#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <stdint.h>

#pragma pack(push, 1)

typedef struct {
  uint16_t source;
  uint16_t dest;
  uint32_t client_seq;
  uint32_t serv_seq;
} tcp_conn_t;

typedef struct {
  // All must be in network endian
  uint8_t h_source[6];
  uint8_t h_dest[6];
  uint8_t source[4];
  uint8_t dest[4];
} endpoint_addr_t;

struct endpoint_hdr {
  struct ethhdr eth;
  struct iphdr ip;
  tcp_conn_t conn;
};

#pragma pack(pop)

// First functions

int set_handshake(int sock, const struct sockaddr_ll *sa,
                  const endpoint_addr_t *ep, tcp_conn_t *conn);

// Parsers

int parse_tcpip(const void *ptr, size_t s, struct endpoint_hdr *ep);

#endif
