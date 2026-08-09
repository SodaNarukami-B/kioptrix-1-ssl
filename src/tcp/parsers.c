// Here's additional sub-module for module.c. It's needed for better
// readabbility. Here we need to realize parse functions for RECEIVED headers in
// tcp handshake like iphdr and tcphdr

#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Aliases
#include "./module_ptr.h"

int _parse_iphdr(const struct iphdr *hdr, uint8_t *opts_out[40]) {

  const size_t total_length = hdr->ihl * 4;
  if (total_length == sizeof(struct iphdr))
    return 0; // No options

  const size_t total_options_length = total_length - sizeof(struct iphdr);

  uint8_t *opt_ptr = (uint8_t *)hdr + sizeof(struct iphdr);

  size_t parsed_bytes = 0;
  int opt_count = 0;

  while (parsed_bytes < total_length && opt_count < 40) {
    if (*opt_ptr == 0)
      break;

    if (*opt_ptr == 1) {
      opt_ptr++;
      parsed_bytes++;
      continue;
    };

    uint8_t len = *(opt_ptr + 1);

    if (len < 2 || (parsed_bytes + len) > total_options_length) {
      printf("[parser/WARN]: bad option len\n");
      break;
    };

    opts_out[opt_count] = opt_ptr;
    opt_count++;

    opt_ptr += len;
    parsed_bytes += len;
  };

  return opt_count;
};

#ifdef BUILD_TEST

int main() {
  uint8_t buff[sizeof(struct iphdr) + 40] = {0};
  int options = 3;

  struct iphdr *hdr = (struct iphdr *)buff;
  hdr->ihl = (sizeof(struct iphdr) + 16) / 4;

  uint8_t options_data[] = {0x07, 0x07, 0x08, 0xC0, 0xA8, 0x01, 0x01,

                            0x89, 0x03, 0x04,

                            0x44, 0x06, 0x05, 0x01, 0xAA, 0xBB};
  memcpy(buff + sizeof(struct iphdr), options_data, sizeof(options_data));

  uint8_t *opts[40] = {0};

  printf("in_opts=%d\n", options);
  int opt_count = _parse_iphdr((struct iphdr *)buff, opts);
  printf("prsd_opts=%d\n", opt_count);

  for (int i = 0; i < opt_count; i++) {
    uint8_t *ptr = opts[i];

    printf("{\n\tOption: %02x\n\tLen: %d\n\tData: ", *(ptr), *(ptr + 1));
    for (int d = 0; d < *(ptr + 1) - 2; d++) {
      printf("%02x%s", *(ptr + 2 + d),
             ((d + 1) == *(ptr + 1) - 2) ? "\n}\n" : " ");
    };
  };

  return 0;
};

#endif

/* EOF */
