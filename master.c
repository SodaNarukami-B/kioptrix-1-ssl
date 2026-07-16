#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/socket.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "./src/tcp/module_ptr.h"

const char *addr = "192.168.1.16";
const char *mac = "\xbc\x38\x98\xa0\x6c\xfc";

int getsock() {
  int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock < 0) {
    printf("[master/ERROR] : socket error\n");
    return -1;
  };

  return sock;
};

int main() {
  printf("[master/INFO] : Started.\n");

  int sock = getsock();
  if (sock < 0) {
    return -1;
  };

  struct sockaddr_ll sa;
  memset(&sa, 0, sizeof(struct sockaddr_ll));

  sa.sll_family = AF_PACKET;
  sa.sll_ifindex = if_nametoindex("enp0s3");
  sa.sll_protocol = htons(ETH_P_IP);
  sa.sll_halen = 6;

  memcpy(sa.sll_addr, mac, 6);

  tcp_handshake(sock, &sa);
  printf("[master/INFO] : done\n");

  return 0;
};
