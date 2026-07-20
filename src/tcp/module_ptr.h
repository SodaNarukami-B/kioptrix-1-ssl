#ifndef TCP
#define TCP

#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <stdint.h>

int tcp_handshake(int sock, struct sockaddr_ll *sa);

/* debug  */
int _syn(int sock, struct sockaddr_ll *sa, struct ethhdr *eth,
         struct iphdr *ip);

#endif
