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

struct packet_t {
  struct ethhdr eth;
  struct iphdr ip;
  struct tcphdr tcp;
  uint8_t zero;
};

struct ps_header {
  uint32_t source_address;
  uint32_t dest_address;
  uint8_t place_holder;
  uint8_t proto;
  uint16_t tcp_length;
};

#pragma pack(pop)

const uint8_t my_mac[] = "\x08\x00\x27\xc9\xb7\xe3";
const uint8_t tar_mac[] = "\xbc\x38\x98\xa0\x6c\xfc";

const char *my_ip = "192.168.1.5";
const char *tar_ip = "192.168.1.16";

uint16_t get_checksum(uint16_t *addr, size_t count) {
  uint32_t big_sum = 0;

  while (count > 1) {
    big_sum += *addr++;
    count -= 2;
  }

  if (count > 0) {
    big_sum += *(uint8_t *)addr;
  };

  while (big_sum >> 16) {
    big_sum = (big_sum & 0xffff) + (big_sum >> 16);
  };

  return (uint16_t)(~big_sum);
};

int tcp_handshake(int sock, struct sockaddr_ll *sa, uint32_t eip) {
  struct packet_t packet;
  struct ps_header pshdr;
  memset(&packet, 0, sizeof(struct packet_t));
  memset(&pshdr, 0, sizeof(struct ps_header));

  // NOTE: Syncronize

  // Eth header
  memcpy(packet.eth.h_dest, tar_mac, 6);
  memcpy(packet.eth.h_source, my_mac, 6);
  packet.eth.h_proto = htons(ETH_P_IP);

  // Ip Header
  packet.ip.version = 4;
  packet.ip.ihl = 5;
  packet.ip.tot_len =
      sizeof(struct iphdr) + sizeof(struct tcphdr); // XXX: NOT IN ALL CASES
  packet.ip.frag_off = 0;
  packet.ip.ttl = 255;
  packet.ip.protocol = IPPROTO_TCP;

  inet_pton(AF_INET, my_ip, &packet.ip.saddr);
  inet_pton(AF_INET, tar_ip, &packet.ip.daddr);

  packet.ip.check = get_checksum((uint16_t *)&packet.ip, sizeof(struct iphdr));

  // Pseudo header
  inet_pton(AF_INET, my_ip, (uint8_t *)&pshdr.source_address);
  inet_pton(AF_INET, tar_ip, (uint8_t *)&pshdr.dest_address);
  pshdr.proto = IPPROTO_TCP;
  pshdr.tcp_length = htons(&packet.zero - (uint8_t *)&packet.tcp);

  // Tcp header

  packet.tcp.th_sport = htons(443);
  packet.tcp.th_dport = htons(60001);
  packet.tcp.seq = htonl(40001);
  packet.tcp.doff = (&packet.zero - (uint8_t *)&packet.tcp) / 4;
  packet.tcp.syn = 1;
  packet.tcp.window = htons(65535);
  packet.tcp.check = 0;
  packet.tcp.urg = 0;
  packet.tcp.urg_ptr = 0;

  // Tcp checksum
  uint8_t *checksum_buffer =
      (uint8_t *)calloc(1, sizeof(struct ps_header) + sizeof(struct tcphdr));
  memcpy(checksum_buffer, (uint8_t *)&pshdr, sizeof(struct ps_header));
  memcpy(checksum_buffer + sizeof(struct ps_header), (uint8_t *)&packet.tcp,
         sizeof(struct tcphdr));

  packet.tcp.check = get_checksum((uint16_t *)checksum_buffer,
                                  &packet.zero - (uint8_t *)&packet.tcp +
                                      sizeof(struct ps_header));

  int send_val = sendto(sock, &packet, sizeof(struct packet_t) - 1, 0,
                        (struct sockaddr *)&sa, sizeof(struct sockaddr));

  if (send_val <= 0) {
    printf("[TH/ERROR] : Syncronize failed\n");
  };

  free(checksum_buffer);
  return 0;
};
