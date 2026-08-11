// Here's additional sub-module for module.c. It's needed for better
// readabbility. Here we need to realize parse functions for RECEIVED headers in
// tcp handshake like iphdr and tcphdr

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Aliases
#include "./module_ptr.h"

// XXX: Bad code: no initalization place

int _parse_iphdr(const struct iphdr *hdr, uint8_t *opts_out[40]) {
  // NOTE:                                         ^^^^^^^^^^^^
  //                                               Nice practice

  const size_t total_length = hdr->ihl * 4;
  if (total_length == sizeof(struct iphdr))
    return 0; // No options

  const size_t total_options_length = total_length - sizeof(struct iphdr);

  uint8_t *opt_ptr = (uint8_t *)hdr + sizeof(struct iphdr);

  size_t parsed_bytes = 0;
  int opt_count = 0;

  while (parsed_bytes < total_length && opt_count < 40) {
    if (*opt_ptr == 0)
      break;

    if (*opt_ptr == 1) {
      opt_ptr++;
      parsed_bytes++;
      continue;
    };

    uint8_t len = *(opt_ptr + 1);

    if (len < 2 || (parsed_bytes + len) > total_options_length) {
      printf("[parser/WARN]: failed to parse ip header options - bad options "
             "length\n");
      break;
    };

    opts_out[opt_count] = opt_ptr;
    opt_count++;

    opt_ptr += len;
    parsed_bytes += len;
  };

  return opt_count;
};

// XXX: To much args expected too
int parse_tcpip_fields(const void *hdrs, const size_t size,
                       const struct ethhdr *eth, const struct iphdr *ip,
                       TCP_CONN *tcp_conn, void *ip_opts_out[40],
                       int ip_opts_c_out) {
  struct ethhdr *r_eth = (struct ethhdr *)hdrs;
  struct iphdr *r_ip = (struct iphdr *)(hdrs + sizeof(struct ethhdr));

  // XXX: I think is a bad practice
  ip_opts_c_out = _parse_iphdr(ip, (uint8_t **)ip_opts_out);

  struct tcphdr *r_tcp =
      (struct tcphdr *)(hdrs + sizeof(struct ethhdr) + ip->ihl * 4);

  // eth
  if (ntohs(r_eth->h_proto) != ETH_P_IP)
    return -1;
  printf("1"); // XXX: Forgotten debug code

  if (memcmp(r_eth->h_source, eth->h_dest, 6) != 0)
    return -1;
  printf("2");

  if (memcmp(r_eth->h_dest, eth->h_source, 6) != 0)
    return -1;
  printf("3");

  // ip
  if (r_ip->version != 4)
    return -1;
  printf("4");

  if (r_ip->protocol != IPPROTO_TCP)
    return -1;
  printf("5");

  if (r_ip->saddr != ip->daddr)
    return -1;
  printf("6");

  if (r_ip->daddr != ip->saddr)
    return -1;
  printf("7");

  // tcp
  if (r_tcp->source != tcp_conn->dest)
    return -1;
  printf("8");

  if (r_tcp->dest != tcp_conn->source)
    return -1;
  printf("9");

  if (ntohl(r_tcp->ack_seq) != (tcp_conn->client_seq + 1))
    return -1;
  printf("10");

  tcp_conn->serv_seq = ntohl(r_tcp->seq);

  if (!(r_tcp->syn && r_tcp->ack) || r_tcp->fin)
    return -1;
  printf("11");

  return 0;
};

// NOTE: Very good practice
#ifdef BUILD_TEST

int main() {
  uint8_t buff[sizeof(struct iphdr) + 40] = {0};
  int options = 3;

  struct iphdr *hdr = (struct iphdr *)buff;
  hdr->ihl = (sizeof(struct iphdr) + 16) / 4;

  uint8_t options_data[] = {0x07, 0x07, 0x08, 0xC0, 0xA8, 0x01, 0x01,

                            0x89, 0x03, 0x04,

                            0x44, 0x06, 0x05, 0x01, 0xAA, 0xBB};
  memcpy(buff + sizeof(struct iphdr), options_data, sizeof(options_data));

  uint8_t *opts[40] = {0};

  printf("in_opts=%d\n", options);
  int opt_count = _parse_iphdr((struct iphdr *)buff, opts);
  printf("prsd_opts=%d\n", opt_count);

  for (int i = 0; i < opt_count; i++) {
    uint8_t *ptr = opts[i];

    printf("{\n\tOption: %02x\n\tLen: %d\n\tData: ", *(ptr), *(ptr + 1));
    for (int d = 0; d < *(ptr + 1) - 2; d++) {
      printf("%02x%s", *(ptr + 2 + d),
             ((d + 1) == *(ptr + 1) - 2) ? "\n}\n" : " ");
    };
  };

  return 0;
};

#endif

// NOTE: Good practice too

/* EOF */
