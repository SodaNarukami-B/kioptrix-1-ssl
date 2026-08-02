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
//   uint8_t buffer[];
//   _syn(&buffer);
//   if (_syn_acked) {
//     _ack();
//   }
// };

// Realization

#pragma pack(push, 1)

// Main header structure (eth + ip + tcp)
struct tcp_pack_t {
  struct ethhdr eth;
  struct iphdr ip;
  struct tcphdr tcp;
};

struct pshdr {
  uint32_t saddr;
  uint32_t daddr;
  uint8_t zero;
  uint8_t proto;
  uint16_t tcp_len;
};

#pragma pack(pop)

// NOTE: Initialization / callable talbe
int _syn(int sock, struct ethhdr *eth, struct iphdr *ip, struct tcp_conn_t *tcp,
         struct sockaddr_ll *sa);
int _r_syn_ack(int sock, void *buf, size_t buf_size, struct ethhdr *eth,
               struct iphdr *ip, struct tcp_conn_t *tcp_conn);
int _ack(int sock, struct ethhdr *eth, struct iphdr *ip, struct tcp_conn_t *tcp,
         struct sockaddr_ll *sa);
int set_handshake(int sock, struct ethhdr *eth, struct iphdr *ip,
                  struct tcp_conn_t *tcp, struct sockaddr_ll *sa);
uint16_t get_checksum(void *ptr, size_t len);

// NOTE: Realization | Main thread
int set_handshake(int sock, struct ethhdr *eth, struct iphdr *ip,
                  struct tcp_conn_t *tcp_conn, struct sockaddr_ll *sa) {

  uint8_t recv_buffer[1024] = {0};

  if (_syn(sock, eth, ip, tcp_conn, sa) < 0)
    return -1;

  while (1) {
    if (_r_syn_ack(sock, recv_buffer, 1024, eth, ip, tcp_conn) == 0)
      break;
    memset(recv_buffer, 0, 1024);
  };

  // _ack(sock, eth, ip, tcp_conn, sa);
  return 0;
};

// NOTE: Realization / child functions
int _syn(int sock, struct ethhdr *eth, struct iphdr *ip,
         struct tcp_conn_t *tcp_conn, struct sockaddr_ll *sa) {
  struct tcp_pack_t pack;
  memset(&pack, 0, sizeof(struct tcp_pack_t));

  // ethhdr
  memcpy(pack.eth.h_dest, eth->h_dest, 6);
  memcpy(pack.eth.h_source, eth->h_source, 6);
  pack.eth.h_proto = htons(ETH_P_IP);

  // iphdr
  uint16_t tcp_ip_len =
      htons(sizeof(struct tcp_pack_t) - sizeof(struct ethhdr));

  pack.ip.version = ip->version;
  pack.ip.ihl = ip->ihl;
  pack.ip.tot_len = tcp_ip_len;
  pack.ip.ttl = ip->ttl;
  pack.ip.protocol = ip->protocol;
  // For correctly checksum calculating, we setting zero checksum before
  // calculating
  pack.ip.check = 0;
  // Copying addresses
  memcpy((uint8_t *)&pack.ip.saddr, (uint8_t *)&ip->saddr, 4);
  memcpy((uint8_t *)&pack.ip.daddr, (uint8_t *)&ip->daddr, 4);

  // Now we can calc checksum
  pack.ip.check = get_checksum(&pack.ip, sizeof(struct iphdr));

  // tcphdr
  pack.tcp.source = tcp_conn->s_port;
  pack.tcp.dest = tcp_conn->d_port;
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

  // Checksum in tcp need another method for correct calc
  uint8_t checksum_buffer[32];
  memset(checksum_buffer, 0, 32);

  struct pshdr *pseudo = (struct pshdr *)&checksum_buffer;

  memcpy(checksum_buffer + sizeof(struct pshdr), &pack.tcp,
         sizeof(struct tcphdr));

  pseudo->saddr = ip->saddr;
  pseudo->daddr = ip->daddr;
  pseudo->proto = IPPROTO_TCP;
  pseudo->tcp_len = htons(sizeof(struct tcphdr));

  uint16_t tcp_checksum = get_checksum(checksum_buffer, 32);
  pack.tcp.check = tcp_checksum;

  // sending

  if (sendto(sock, &pack, sizeof(struct tcp_pack_t), 0, (struct sockaddr *)sa,
             sizeof(struct sockaddr_ll)) < 0) {
    printf("_syn cannot send packet\n");
    return -1;
  };

  /* Debug */
  printf(">>>\n");
  for (int i = 0; i < 64; i++) {
    printf("%02x%s", *(((uint8_t *)&pack) + i),
           ((i + 1) % 16 == 0 || (i + 1) == 64) ? "\n" : " ");
  };
  printf("\n");

  return 0;
};

int _r_syn_ack(int sock, void *buf, size_t buf_size, struct ethhdr *eth,
               struct iphdr *ip, struct tcp_conn_t *tcp_conn) {
  int res = recvfrom(sock, buf, buf_size, 0, NULL, NULL);
  if (res <= 0) {
    printf("_r_syn_ack cannot receive any data (errcode: %d)\n", res);
    return -1;
  };

  // Eth checking
  struct ethhdr *recv_eth = (struct ethhdr *)buf;

  if (memcmp(recv_eth->h_source, eth->h_dest, 6) != 0)
    return -1;
  printf("h_source & h_dest [+]\n");

  if (memcmp(recv_eth->h_dest, eth->h_source, 6) != 0)
    return -1;
  printf("h_dest & h_souce [+]\n");

  if (recv_eth->h_proto != htons(ETH_P_IP))
    return -1;
  printf("h_proto [+]\n");

  // Ip checking
  struct iphdr *recv_ip = (struct iphdr *)(buf + sizeof(struct ethhdr));

  if (recv_ip->version != 4)
    return -1;
  printf("IP version [+]\n");

  if (recv_ip->protocol != IPPROTO_TCP)
    return -1;
  printf("IP protocol [+]\n");

  if (memcmp(&recv_ip->saddr, &ip->daddr, 4) != 0)
    return -1;
  printf("source & dest [+]\n");

  if (memcmp(&recv_ip->daddr, &ip->saddr, 4) != 0)
    return -1;
  printf("dest & source [+]\n");

  // Tcp checking
  struct tcphdr *recv_tcp =
      (struct tcphdr *)(buf + sizeof(struct ethhdr) + sizeof(struct iphdr));

  if (recv_tcp->source != tcp_conn->d_port)
    return -1;
  printf("s_port & d_port [+]\n");

  if (recv_tcp->dest != tcp_conn->s_port)
    return -1;
  printf("d_port & s_port [+]\n");

  if (ntohl(recv_tcp->ack_seq) != tcp_conn->client_seq + 1)
    return -1;
  printf("ack_seq is equal cliect seq + 1 [+]\n");

  tcp_conn->serv_seq = ntohl(recv_tcp->seq);

  if (!recv_tcp->syn || !recv_tcp->ack)
    return -1;
  printf("packet is syn-ack [+]\n");

  return 0;
};

uint16_t get_checksum(void *ptr, size_t len) {
  const uint16_t *p = (uint16_t *)ptr;

  uint32_t result = 0;

  while (len > 1) {
    result += *p++;
    len -= 2;
  };

  if (len > 0) {
    result += *(const uint8_t *)p;
  };

  while (result >> 16) {
    result = (result & 0xffff) + (result >> 16);
  };

  return (uint16_t)(~result); // In host order
};

;
