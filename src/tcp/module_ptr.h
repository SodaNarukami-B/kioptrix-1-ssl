#ifndef TCP
#define TCP

#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <stdint.h>

#define SYN_ACK 0x12
#define FIN 0x01
#define RST 0x04

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
  uint32_t source;
  uint32_t dest;
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

int parse_tcpip(const void *hdr, size_t s, const struct endpoint_hdr *ep,
                tcp_conn_t *conn, uint8_t th_flags);

#endif
