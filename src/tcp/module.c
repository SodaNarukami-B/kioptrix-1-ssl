#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../lib/tcp/tcp.h"
#include "./module_ptr.h"

#pragma pack(push, 1)

struct packet_t {
  struct ethhdr eth;
  // FIXME: make iphdr
  TCP_HEADER tcp;
};

#pragma pack(pop)

int set_tcp_connection(int sock, struct sockaddr_ll *sa, uint32_t eip) {
  struct packet_t packet;
  memset(&packet, 0, sizeof(struct packet_t));

  return 0;
};
