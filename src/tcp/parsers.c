// Here's additional sub-module for module.c. It's needed for better
// readabbility. Here we need to realize parse functions for RECEIVED headers in
// tcp handshake like iphdr and tcphdr

#include <netinet/ip.h>
#include <stdio.h>
#include <string.h>

// Aliases
#include "./module_ptr.h"

/* TODO: Make a structure for returning a size of all options and array with
   pointers to that options and return that structure in parser. It's need to
   give main function abillity to choose what that would do with options (skip
   or parse and determinie behaviour depending to options)
*/
uint8_t *_parse_iphdr(const struct iphdr *hdr) {

  // Collecting options
  uint8_t *options_ptrs[40] = {0};

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

    options_ptrs[opt_count] = opt_ptr;
    opt_count++;

    opt_ptr++;
    parsed_bytes += len;
  };

  // Now we can parse that options
  // (DEV)
};
