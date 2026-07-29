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
int _ack(int sock, struct ethhdr *eth, struct iphdr *ip, struct tcp_conn_t *tcp,
         struct sockaddr_ll *sa);
int set_handshake(int sock, struct ethhdr *eth, struct iphdr *ip,
                  struct tcp_conn_t *tcp, struct sockaddr_ll *sa);
uint16_t get_checksum(void *ptr, size_t len);

// NOTE: Realization
int set_handshake(int sock, struct ethhdr *eth, struct iphdr *ip,
                  struct tcp_conn_t *tcp_conn, struct sockaddr_ll *sa) {

  if (_syn(sock, eth, ip, tcp_conn, sa) < 0)
    return -1;

  // _ack(sock, eth, ip, tcp_conn, sa);

  return 0;
};

// NOTE: Realization / child functions

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

  // Now we can calc checksum
  pack.ip.check = htons(get_checksum(&pack.ip, sizeof(struct iphdr)));

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

  uint16_t tcp_checksum = htons(get_checksum(checksum_buffer, 32));
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

  // receiving
  uint8_t recv_buffer[256] = {0};

  if (recvfrom(sock, recv_buffer, 256, 0, NULL, NULL) < 0) {
    printf("_syn cannot receive any data (timeout connection or connection "
           "reseted)\n");
    return -1;
  };

  // XXX: Maybe I should make receiving and validating in another function
  // named
  // "_r_syn_ack" ??? -- Yeah, i think you need. Try to realize that idea in
  // next commit

  /* Debug */
  printf("<<<\n");
  for (int i = 0; i < 64; i++) {
    printf("%02x%s", recv_buffer[i],
           ((i + 1) % 16 == 0 || (i + 1) == 64) ? "\n" : " ");
  };
};
