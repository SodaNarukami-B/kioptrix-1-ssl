#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "./module_ptr.h"

#pragma pack(push, 1)

struct tcp_packet {
  uint16_t source_port;
  uint16_t dest_port;
  uint32_t sequence_number;
  uint32_t aknowledgment_number;
  uint8_t reserved;
  uint8_t tcp_flag;
  uint16_t window;
  uint16_t checksum;
  uint16_t urgent_pointer;
  uint32_t options;
};

struct packet_t {
  struct ethhdr eth;
  // FIXME: make iphdr
  struct tcp_packet tcp;
  uint8_t data[];
};

#pragma pack(pop)

int set_tcp_connection(int sock, struct sockaddr_ll *sa, uint32_t eip) {
  system("echo 'pass'");
  return 0;
};
