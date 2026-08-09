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

struct ip_opt {
  uint8_t opt;
  uint8_t len;
  uint8_t *body;
};

struct ip_options {
  size_t count;
  struct ip_opt *opts;
};

#pragma pack(pop)

// Main function
int set_handshake(int sock, const struct sockaddr_ll *sa,
                  const struct ethhdr *eth, const struct iphdr *ip,
                  TCP_CONN *tcp_conn);

// Parsers
//
// Takes poiter to header and pointer

int parse_tcpip_fields(const void *hdrs, const size_t size,
                       const struct ethhdr *eth, const struct iphdr *ip,
                       TCP_CONN *tcp_conn, void *ip_opts_out[40],
                       int ip_opts_c_out);
// int _parse_tcphdr(const struct tcphdr *hdr);

#endif
