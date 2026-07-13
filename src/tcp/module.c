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
};

#pragma pack(pop)

const uint8_t my_mac[] = "\x08\x00\x27\xc9\xb7\xe3";
const uint8_t tar_mac[] = "\xbc\x38\x98\xa0\x6c\xfc";

const char *my_ip = "192.168.1.5";
const char *tar_ip = "192.168.1.16";

uint16_t ip_checksum_calculate(uint16_t *addr, size_t cont); // FIXME:

int set_tcp_connection(int sock, struct sockaddr_ll *sa, uint32_t eip) {
  struct packet_t packet;
  memset(&packet, 0, sizeof(struct packet_t));

  // Eth header
  memcpy(packet.eth.h_dest, tar_mac, 6);
  memcpy(packet.eth.h_source, my_mac, 6);
  packet.eth.h_proto = htons(ETH_P_IP);

  // Ip Header
  packet.ip.version = 4;
  packet.ip.ihl = 5;
  packet.ip.frag_off = 0;
  packet.ip.ttl = 255;
  packet.ip.protocol = IPPROTO_TCP;
  packet.ip.check = 0; // FIXME: Set valid checksum for ip.check

  inet_pton(AF_INET, my_ip, &packet.ip.saddr);
  inet_pton(AF_INET, tar_ip, &packet.ip.daddr);

  // Tcp header
  // FIXME: Fill tcp header

  return 0;
};
