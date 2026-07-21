#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <sys/socket.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "./src/tcp/module_ptr.h"

const char *saddr = "192.168.1.8";
const char *daddr = "192.168.1.16";

const uint8_t shaddr[6] = {0x08, 0x00, 0x27, 0xc9, 0xb7, 0xe3};
const uint8_t dhaddr[6] = {0xbc, 0x38, 0x98, 0xa0, 0x6c, 0xfc};

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
  memcpy(sa.sll_addr, dhaddr, 6);

  // in fact, eth and ip headers inited in this place just for more read-ability
  // and more comfortable passing the ip and mac addresses
  struct ethhdr eth;
  memset(&eth, 0, sizeof(struct ethhdr));
  struct iphdr ip;
  memset(&ip, 0, sizeof(struct iphdr));

  memcpy(eth.h_source, shaddr, 6);
  memcpy(eth.h_dest, dhaddr, 6);
  eth.h_proto = htons(ETH_P_IP); // 0x0800

  ip.version = 4;
  ip.ihl = sizeof(struct iphdr) / 4;
  // ip tol setting in _syn, becouse we don't know finaly packet size
  ip.ttl = 0xff;
  ip.protocol = IPPROTO_TCP;
  // addresses
  inet_pton(AF_INET, saddr, (uint8_t *)&ip.saddr);
  inet_pton(AF_INET, daddr, (uint8_t *)&ip.daddr);

  if (_sync(sock, &sa, &eth, &ip) < 0) {
    return -1;
  };
  printf("[master/INFO] : done\n");

  return 0;
};
