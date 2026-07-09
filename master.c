#include <arpa/inet.h>
#include <sys/socket.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char *addr = "192.168.1.16";
const uint16_t port = 443;

int getsock() {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    printf("[master/ERROR] : socket error\n");
    return -1;
  };

  // TODO: timeouts for socket

  return sock;
};

int get_connection(int sock, const char *addr, uint16_t port) {
  // NOTE: Pass the address as a string like "192.168.1.1";
  //       Pass the port in little-endian format

  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(struct sockaddr_in));
  sa.sin_family = AF_INET;

  if (inet_pton(AF_INET, addr, &sa.sin_addr) < 0) {
    printf("[master/ERROR] : invalid address\n");
    return -1;
  }

  sa.sin_port = htons(port);

  if (connect(sock, (struct sockaddr *)&sa, sizeof(struct sockaddr)) < 0) {
    printf("[master/ERROR] : connection error\n");
    return -1;
  };

  return 0;
};

int main() {
  printf("[master/INFO] : Started.\n");

  int sock = getsock();
  if (sock < 0) {
    return -1;
  };

  if (get_connection(sock, addr, port) < 0) {
    return -1;
  };

  printf("[master/INFO] : done\n");

  return 0;
};
