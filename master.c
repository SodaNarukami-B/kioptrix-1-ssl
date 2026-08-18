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

// ----------------------------------------------------------
const char *source = "192.168.1.3";
const char *dest = "192.168.1.104";

const uint8_t h_source[6] = {0x34, 0x5a, 0x60, 0x23, 0x12, 0xd0};
const uint8_t h_dest[6] = {0x00, 0x0c, 0x29, 0xc7, 0xf6, 0xd2};

// -----------------------------------------------------------

int getsock() {
  int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock < 0) {
    printf("[master/ERROR] : socket error\n");
    return -1;
  };

  return sock;
};

// -----------------------------------------------------------

int main(int argc, char *argv[]) {

  // TODO: I think make a minimal user interface is a good idea, but not now.
  // You can do that if you don't know what to do now

  // -------------------------------------------------------
  printf("[master/INFO]: Started.\n");

  int sock = getsock();
  if (sock < 0) {
    return -1;
  };

  struct sockaddr_ll sa;
  memset(&sa, 0, sizeof(struct sockaddr_ll));

  sa.sll_family = AF_PACKET;
  sa.sll_ifindex = if_nametoindex("enp3s0");
  sa.sll_protocol = htons(ETH_P_IP);
  sa.sll_halen = 6;
  memcpy(sa.sll_addr, h_dest, 6);

  //---------------------------------------------------------

  endpoint_addr_t ep_addr;

  memcpy(ep_addr.h_source, h_source, 6);
  memcpy(ep_addr.h_dest, h_dest, 6);
  inet_pton(AF_INET, source, &ep_addr.source);
  inet_pton(AF_INET, dest, &ep_addr.dest);

  tcp_conn_t conn;

  conn.source = htons(60001);
  conn.dest = htons(443);
  conn.client_seq = 0x00004443;
  conn.serv_seq = 0;

  // -------------------------------------------------------

  int handshake_report = set_handshake(sock, &sa, &ep_addr, &conn);

  if (handshake_report < 0) {
    printf("[master/ERROR]: tcphandshake failed\n");
    return -1;
  };

  printf("[master/INFO]: done\n");

  return 0;

  // --------------------------------------------------------
};
