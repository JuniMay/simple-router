#include "router.h"

#include <stdio.h>

// no deprecated warning
#pragma warning(disable : 4996)

int main() {
  arp_cache_init(&arp_cache);
  route_table_init(&route_table);

  find_all_devices(&alldevsp);
  show_all_devices(alldevsp);

  cli();

  arp_cache_free_all(&arp_cache);
  route_table_free_all(&route_table);

  free_all_devices(alldevsp);

  return 0;
}