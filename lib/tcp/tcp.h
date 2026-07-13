#ifndef TCPH
#define TCPH

#include <stdint.h>
#include <stdio.h>

#pragma pack(push, 1)

typedef struct {
  uint16_t source_port;
  uint16_t dest_port;
  uint32_t seq_number;
  uint32_t ack_number;
  uint8_t data_offset_and_reserved;
  uint8_t falgs;
  uint16_t window;
  uint16_t checksum;
  uint16_t urgent;
  uint32_t options;
  uint8_t data[];
} TCP_HEADER;

#pragma pack(pop, 1)

int get_checksum(uint8_t *packet, size_t size);

#endif
