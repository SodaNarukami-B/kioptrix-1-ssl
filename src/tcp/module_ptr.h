#ifndef TCP
#define TCP

#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <stdint.h>

int tcp_handshake(int sock, struct sockaddr_ll *sa);

/* debug  */
int _sync(int sock, struct sockaddr_ll *sa, struct ethhdr *eth,
          struct iphdr *ip);
uint16_t get_check(const uint8_t *addr, size_t count);

#endif
