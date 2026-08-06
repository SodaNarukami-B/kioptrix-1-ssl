// Here's additional sub-module for module.c. It's needed for better
// readabbility. Here we need to realize parse functions for RECEIVED headers in
// tcp handshake like iphdr and tcphdr

#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Aliases
#include "./module_ptr.h"

// TODO: Test with self-maded ip headers with different optinons (use GDB
// brooo);

uint8_t _parse_iphdr(const struct iphdr *hdr, const uint8_t *opts_out[40]) {

  // Collecting options

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

    uint8_t len = *(opt_ptr + 1); // We NEED to make this variable for then
                                  // alloc a right size for structure

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

  // In-dev process:
  // Soda >> Like we first checking that optinon is not a 00 or 01, then we
  // grabbing length of option from header's memory and allocating NEW memory
  // with size of option; copying optinon to 'accessed' memory, filling the
  // structure of ip option and adding pointer to that structure to array with
  // pointers to optinons
  //
  // It's not a final logic of this place btw and this place is NOT done. Just
  // making drafts
  //
  // Soda >> Boolshit. It's anti-pattern. You need just return the array with
  // pointers to options inside a header, do NOT alloc a new memory just for
  // user protecting
};
