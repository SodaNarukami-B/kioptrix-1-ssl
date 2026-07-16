#ifndef TCP
#define TCP

#include <linux/if_packet.h>
#include <stdint.h>

int tcp_handshake(int sock, struct sockaddr_ll *sa, uint32_t eip);

#endif
