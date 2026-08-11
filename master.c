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
const char *source = "192.168.1.11";
const char *dest = "192.168.1.42";

const uint8_t h_source[6] = {0x08, 0x00, 0x27, 0xc9, 0xb7, 0xe3};
const uint8_t h_dest[6] = {0xbc, 0x38, 0x98, 0xa0, 0x6c, 0xfc};

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
  sa.sll_ifindex = if_nametoindex("enp0s3");
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
