#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "./module_ptr.h"

#pragma pack(push, 1)

struct tcph_packet_t {
  struct ethhdr eth;
  struct iphdr ip;
  struct tcphdr tcp;
};

struct pseudo_h_t {
  uint32_t saddr;
  uint32_t daddr;
  uint8_t pad;
  uint8_t proto;
  uint16_t tcp_length;
};

#pragma pack(pop, 1)

int send_pack(int sock, uint8_t *buf, size_t buf_s, struct sockaddr_ll *sa);
int recv_pack(int sock, uint8_t *buf, size_t buf_s);
uint16_t get_check(uint16_t *ptr, size_t count);
int _sync(int sock, struct sockaddr_ll *sa, struct ethhdr *eth,
          struct iphdr *ip);

// Tcp handshake steps

int _sync(int sock, struct sockaddr_ll *sa, struct ethhdr *eth,
          struct iphdr *ip) {
  struct tcph_packet_t pack;
  memset(&pack, 0, sizeof(struct tcph_packet_t));

  memcpy(&pack.eth, eth, sizeof(struct ethhdr));
  memcpy(&pack.ip, ip, sizeof(struct iphdr));

  pack.ip.check = 0;

  pack.tcp.source = htons(4444);
  pack.tcp.dest = htons(443);
  pack.tcp.seq = htonl(0x10101010); // Like pattern or smth
  pack.tcp.doff = 5;
  pack.tcp.syn = 1;
  pack.tcp.window = 0xffff;
  pack.tcp.check = 0;

  // checksums
  uint8_t *buffer = (uint8_t *)calloc(1, sizeof(struct iphdr));

  memcpy(buffer, ip, sizeof(struct iphdr));
  pack.ip.check = get_check((uint16_t *)buffer, sizeof(struct iphdr));

  free(buffer);

  size_t tcp_total_len = sizeof(struct pseudo_h_t) + sizeof(struct tcphdr);

  buffer = (uint8_t *)calloc(1, tcp_total_len);

  struct pseudo_h_t *pseudo_h = (struct pseudo_h_t *)buffer;

  memcpy(&pseudo_h->saddr, &ip->saddr, 4);
  memcpy(&pseudo_h->daddr, &ip->daddr, 4);
  pseudo_h->proto = IPPROTO_TCP;
  pseudo_h->tcp_length = htons(sizeof(struct tcphdr));

  memcpy(buffer + sizeof(struct pseudo_h_t), &pack.tcp, sizeof(struct tcphdr));

  pack.tcp.check = get_check((uint16_t *)buffer, tcp_total_len);

  free(buffer);

  // sending & recving

  if (send_pack(sock, (uint8_t *)&pack, sizeof(struct tcph_packet_t), sa) < 0)
    return -1;

  uint8_t *recv_buffer = (uint8_t *)calloc(1, 128);
  struct tcph_packet_t *r_pack = (struct tcph_packet_t *)recv_buffer;

  while (1) {
    if (recv_pack(sock, recv_buffer, 128) < 0)
      return -1;

    if (r_pack->ip.protocol != IPPROTO_TCP)
      continue;

    if (memcmp(r_pack->eth.h_dest, eth->h_source, 6) != 0)
      continue;

    if (memcmp(&r_pack->ip.daddr, &ip->saddr, 4) != 0)
      continue;

    if (r_pack->tcp.dest != pack.tcp.source)
      continue;

    printf("[syn/INFO]: packet received...\n");

    for (int i = 0; i < 128; i++) {
      printf("%02x%s", recv_buffer[i], ((i + 1) % 16 == 0) ? "\n" : " ");
    };
  };
};

int send_pack(int sock, uint8_t *buf, size_t buf_s, struct sockaddr_ll *sa) {
  int sended = sendto(sock, buf, buf_s, 0, (struct sockaddr *)sa,
                      sizeof(struct sockaddr_ll));
  if (sended <= 0) {
    fprintf(stderr, "[sock/ERROR]: sending failed\n");
    return -1;
  };

  return 0;
};

int recv_pack(int sock, uint8_t *buf, size_t buf_s) {
  int recved = recvfrom(sock, buf, buf_s, 0, NULL, NULL);

  if (recved <= 0) {
    fprintf(stderr, "[sock/ERROR]: receiving failed\n");
    return -1;
  };

  return 0;
};

uint16_t get_check(uint16_t *ptr, size_t count) {
  uint32_t result = 0;

  while (count > 1) {
    result += *ptr++;
    count -= 2;
  };

  if (count > 0) {
    result += *(uint8_t *)ptr;
  };

  while (result >> 16) {
    result = (result & 0xffff) + (result >> 16);
  };

  return (uint16_t)(~result);
};
