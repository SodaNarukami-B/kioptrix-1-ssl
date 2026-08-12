#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "./module_ptr.h"

int parse_tcpip(const void *hdr, size_t s, const struct endpoint_hdr *ep,
                tcp_conn_t *conn, uint8_t th_flags) {
  size_t min_size =
      sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);

  if (s < min_size)
    return -1;

  // --------------------------------------------------------------
  const uint8_t *ptr = (const uint8_t *)hdr;

  struct ethhdr *eth = (struct ethhdr *)ptr;
  struct iphdr *ip = (struct iphdr *)(ptr + sizeof(struct ethhdr));
  struct tcphdr *tcp =
      (struct tcphdr *)(ptr + sizeof(struct ethhdr) + ip->ihl * 4);

  // ---------------------------------------------------------------

  int debug_val = 0;

  if (eth->h_proto != ep->eth.h_proto)
    return -1;

  if (memcmp(eth->h_source, ep->eth.h_dest, 6) != 0)
    return -1;

  if (memcmp(eth->h_dest, ep->eth.h_source, 6) != 0)
    return -1;

  // ---------------------------------------------------------------

  if (ip->version != ep->ip.version)
    return -1;

  if (ip->ttl < 1)
    return -1;

  if (ip->protocol != ep->ip.protocol)
    return -1;

  if (ip->saddr != ep->ip.daddr || ip->daddr != ep->ip.saddr)
    return -1;

  // ---------------------------------------------------------------

  if (tcp->source != ep->conn.dest || tcp->dest != ep->conn.source)
    return -1;

  if (ntohl(tcp->ack_seq) != ep->conn.client_seq + 1)
    return -1;

  conn->serv_seq = ntohl(tcp->seq);

  // You can place here any flags that you want
  if (tcp->th_flags != th_flags)
    return -1;

  return 0;
};
