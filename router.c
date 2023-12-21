#include "router.h"

#include <pcap/pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Windows.h"

#pragma comment(lib, "ws2_32.lib")
// no deprecated warning
#pragma warning(disable : 4996)

arp_cache_t arp_cache;
route_table_t route_table;
bool running = false;
pcap_if_t* alldevsp;
mac_addr_t host_mac;
ipv4_addr_t host_ip;

void show_mac_addr(mac_addr_t mac) {
  for (size_t i = 0; i < 6; i++) {
    printf("%02x", mac.addr[i]);
    if (i != 5) {
      printf(":");
    }
  }
}

void send_arp_request(
  pcap_t* handle,
  ipv4_addr_t src_ip,
  const mac_addr_t* src_mac,
  ipv4_addr_t dst_ip
) {
  uint8_t packet[sizeof(ether_hdr_t) + sizeof(arp_packet_t)];

  ether_hdr_t* ether_hdr = (ether_hdr_t*)packet;
  arp_packet_t* arp_packet = (arp_packet_t*)(packet + sizeof(ether_hdr_t));

  // Ethernet header
  memcpy(ether_hdr->dst_mac.addr, "\xff\xff\xff\xff\xff\xff", 6);
  memcpy(ether_hdr->src_mac.addr, src_mac->addr, 6);
  ether_hdr->ether_type = htons(ETHER_TYPE_ARP);

  // ARP packet
  arp_packet->hardware_type = htons(ARP_HARDWARE_TYPE_ETHERNET);
  arp_packet->protocol_type = htons(ETHER_TYPE_IPV4);
  arp_packet->mac_addr_len = 6;
  arp_packet->ip_addr_len = 4;
  arp_packet->operation = htons(ARP_OPERATION_REQUEST);
  memcpy(arp_packet->sender_mac.addr, src_mac->addr, 6);
  arp_packet->sender_ip = src_ip;
  memcpy(arp_packet->target_mac.addr, "\x00\x00\x00\x00\x00\x00", 6);
  arp_packet->target_ip = dst_ip;

  if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
    fprintf(stderr, "Error sending the ARP request: %s\n", pcap_geterr(handle));
  }

  // printf("[ router ] sent arp request\n");
}

int listen_arp_reply(
  pcap_t* handle,
  ipv4_addr_t expected_ip,
  mac_addr_t* out_mac
) {
  size_t cnt = 10;
  while (cnt--) {
    struct pcap_pkthdr* header;
    const uint8_t* packet;
    int result = pcap_next_ex(handle, &header, &packet);

    if (result == -1) {
      fprintf(stderr, "error in pcap_next_ex: %s\n", pcap_geterr(handle));
      return 1;
    }

    if (header->caplen == 0) {
      continue;
    }

    ether_hdr_t* ether_hdr = (ether_hdr_t*)packet;
    arp_packet_t* arp_packet = (arp_packet_t*)(packet + sizeof(ether_hdr_t));

    if (
      // thernet frame type is arp
      ntohs(ether_hdr->ether_type) == ETHER_TYPE_ARP &&
      // arp operation is reply
      ntohs(arp_packet->operation) == ARP_OPERATION_REPLY &&
      // target ip is expected ip
      arp_packet->sender_ip == expected_ip
    ) {
      memcpy(out_mac->addr, arp_packet->sender_mac.addr, 6);

      // sender ip
      uint8_t a = arp_packet->sender_ip & 0xff;
      uint8_t b = (arp_packet->sender_ip >> 8) & 0xff;
      uint8_t c = (arp_packet->sender_ip >> 16) & 0xff;
      uint8_t d = (arp_packet->sender_ip >> 24) & 0xff;

      return 0;
    }
  }

  return 1;
}

int get_host_mac(pcap_t* handle, ipv4_addr_t host_ip, mac_addr_t* out_mac) {
  // the pseudo source mac address
  mac_addr_t pseudo_src_mac;
  // 10.10.10.10
  // just a random ip address
  ipv4_addr_t pseudo_src_ipv4_addr = 0x0a0a0a0a;
  // set mac to be f0:f0:f0:f0:f0:f0
  memset(&pseudo_src_mac, 0xf0, sizeof(pseudo_src_mac));

  get_remote_mac(
    handle, pseudo_src_ipv4_addr, &pseudo_src_mac, host_ip, out_mac
  );

  return 0;
}

int get_remote_mac(
  pcap_t* handle,
  ipv4_addr_t src_ip,
  const mac_addr_t* src_mac,
  ipv4_addr_t dst_ip,
  mac_addr_t* out_mac
) {
  // check arp cache
  arp_entry_t* entry;
  if ((entry = arp_cache_find(&arp_cache, dst_ip)) != NULL) {
    printf(
      "[ router ] found arp entry in cache for %u.%u.%u.%u\n", dst_ip & 0xff,
      (dst_ip >> 8) & 0xff, (dst_ip >> 16) & 0xff, (dst_ip >> 24) & 0xff
    );
    memcpy(out_mac->addr, entry->mac.addr, 6);
    return 0;
  }

  size_t cnt = 10;

  while (cnt--) {
    send_arp_request(handle, src_ip, src_mac, dst_ip);
    if (listen_arp_reply(handle, dst_ip, out_mac) == 0) {
      break;
    }
  }

  if (cnt == 0) {
    return 1;
  }

  arp_entry_t* new_entry = malloc(sizeof(arp_entry_t));
  new_entry->ip = dst_ip;
  memcpy(new_entry->mac.addr, out_mac->addr, 6);
  arp_cache_add(&arp_cache, new_entry);

  return 0;
}

int find_all_devices(pcap_if_t** alldevsp) {
  char errbuf[PCAP_ERRBUF_SIZE];
  if (pcap_findalldevs(alldevsp, errbuf) == -1) {
    fprintf(stderr, "error in pcap_findalldevs: %s\n", errbuf);
    return 1;
  }

  for (pcap_if_t* device = *alldevsp; device != NULL; device = device->next) {
    pcap_addr_t* address = device->addresses;
    for (; address != NULL; address = address->next) {
      if (address->addr->sa_family == AF_INET) {
        ipv4_addr_t ip = ((struct sockaddr_in*)address->addr)->sin_addr.s_addr;
        ipv4_addr_t mask =
          ((struct sockaddr_in*)address->netmask)->sin_addr.s_addr;
        route_entry_t* entry = route_table_alloc();
        entry->dst_ip = ip & mask;
        entry->mask = mask;
        entry->next_hop_ip = ip;
        entry->is_direct = true;
        route_table_add(&route_table, entry);
      }
    }
  }

  return 0;
}

void free_all_devices(pcap_if_t* alldevsp) {
  pcap_freealldevs(alldevsp);
}

void show_all_devices(pcap_if_t* alldevsp) {
  size_t device_count = 1;
  for (pcap_if_t* device = alldevsp; device != NULL; device = device->next) {
    printf("%3zu %20s %s\n", device_count, device->name, device->description);

    pcap_addr_t* address = device->addresses;
    for (; address != NULL; address = address->next) {
      if (address->addr->sa_family == AF_INET) {
        ipv4_addr_t ip = ((struct sockaddr_in*)address->addr)->sin_addr.s_addr;
        ipv4_addr_t mask =
          ((struct sockaddr_in*)address->netmask)->sin_addr.s_addr;
        printf(
          "    ip: %u.%u.%u.%u mask: %u.%u.%u.%u\n", ip & 0xff,
          (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff, mask & 0xff,
          (mask >> 8) & 0xff, (mask >> 16) & 0xff, (mask >> 24) & 0xff
        );
      }
    }

    device_count++;
  }
  printf("total: %zu devices\n", device_count - 1);
}

pcap_if_t* find_device_by_number(pcap_if_t* alldevsp, int number) {
  pcap_if_t* device = alldevsp;
  for (int i = 0; i < number - 1 && device != NULL; i++) {
    device = device->next;
  }
  return device;
}

void show_arp_cache() {
  printf("arp cache:\n");
  arp_entry_t* entry;
  FOR_EACH_ENTRY(entry, &arp_cache.entries, arp_entry_t, link) {
    printf(
      "    ip: %u.%u.%u.%u mac: ", entry->ip & 0xff, (entry->ip >> 8) & 0xff,
      (entry->ip >> 16) & 0xff, (entry->ip >> 24) & 0xff
    );
    show_mac_addr(entry->mac);
    printf("\n");
  }
}

void show_route_table() {
  printf("route table:\n");
  // route_entry_t* entry;
  // FOR_EACH_ENTRY(entry, &route_table.entries, route_entry_t, link) {
  //   printf("    ");
  //   show_route_entry(entry);
  // }

  for (int i = 0; i <= 31; i++) {
    route_hash_t* route_hash = &route_table.tables[i];
    route_entry_t* entry;
    for (int hash = 0; hash < ROUTE_HASH_MODULO; hash++) {
      FOR_EACH_ENTRY(entry, &route_hash->entries[hash], route_entry_t, link) {
        printf("    ");
        show_route_entry(entry);
      }
    }
  }
}

void router_handler(pcap_t* handle) {
  uint8_t buffer[65535];

  while (running) {
    struct pcap_pkthdr* header;
    const uint8_t* packet;
    int result = pcap_next_ex(handle, &header, &packet);

    if (result == -1) {
      fprintf(stderr, "error in pcap_next_ex: %s\n", pcap_geterr(handle));
      return;
    }

    if (header->caplen == 0) {
      continue;
    }

    ether_hdr_t* ether_hdr = (ether_hdr_t*)packet;

    if (ether_hdr == NULL) {
      continue;
    }

    // check ip
    if (ntohs(ether_hdr->ether_type) != ETHER_TYPE_IPV4) {
      continue;
    }

    printf("==============================================================\n");

    ipv4_hdr_t* ipv4_hdr = (ipv4_hdr_t*)(packet + sizeof(ether_hdr_t));

    if (check_checksum(ipv4_hdr) != 0) {
      printf("[ router ] invalid checksum\n");
      continue;
    }

    ipv4_addr_t src_ipv4_addr = ipv4_hdr->src_addr;
    ipv4_addr_t dst_ipv4_addr = ipv4_hdr->dst_addr;

    mac_addr_t src_mac;
    memcpy(src_mac.addr, ether_hdr->src_mac.addr, 6);

    printf("[ router ] received packet from ");
    show_mac_addr(src_mac);
    printf("\n");

    mac_addr_t dst_mac;
    memcpy(dst_mac.addr, ether_hdr->dst_mac.addr, 6);

    if (memcmp(dst_mac.addr, host_mac.addr, 6) != 0) {
      printf("[ router ] to ");
      show_mac_addr(dst_mac);
      printf(", but host mac: ");
      show_mac_addr(host_mac);
      printf("\n");
      continue;
    } else {
      printf("[ router ] to host\n");
    }

    printf(
      "[ router ] received packet from %u.%u.%u.%u to %u.%u.%u.%u\n",
      src_ipv4_addr & 0xff, (src_ipv4_addr >> 8) & 0xff,
      (src_ipv4_addr >> 16) & 0xff, (src_ipv4_addr >> 24) & 0xff,
      dst_ipv4_addr & 0xff, (dst_ipv4_addr >> 8) & 0xff,
      (dst_ipv4_addr >> 16) & 0xff, (dst_ipv4_addr >> 24) & 0xff
    );

    route_entry_t* route_entry = route_table_match(&route_table, dst_ipv4_addr);

    if (route_entry == NULL) {
      printf(
        "[ router ] no route entry found for %u.%u.%u.%u\n",
        dst_ipv4_addr & 0xff, (dst_ipv4_addr >> 8) & 0xff,
        (dst_ipv4_addr >> 16) & 0xff, (dst_ipv4_addr >> 24) & 0xff
      );
      continue;
    }

    printf("[ router ] route entry found: ");
    show_route_entry(route_entry);
    printf("\n");

    ipv4_addr_t next_hop_ip = route_entry->next_hop_ip;

    if (route_entry->is_direct) {
      printf("[ router ] direct route\n");
      next_hop_ip = dst_ipv4_addr;
    }

    // get remote mac
    mac_addr_t remote_mac;
    if (get_remote_mac(handle, host_ip, &host_mac, next_hop_ip, &remote_mac) != 0) {
      printf("[ router ] failed to get remote mac\n");
      continue;
    }

    // send packet
    memcpy(buffer, packet, header->len);

    ether_hdr_t* new_ether_hdr = (ether_hdr_t*)buffer;
    memcpy(new_ether_hdr->dst_mac.addr, remote_mac.addr, 6);
    memcpy(new_ether_hdr->src_mac.addr, host_mac.addr, 6);

    if (pcap_sendpacket(handle, buffer, header->len) != 0) {
      fprintf(stderr, "error in pcap_sendpacket: %s\n", pcap_geterr(handle));
    }

    printf("==============================================================\n");
  }

  pcap_close(handle);
}

void start_routing() {
  printf("[ router ] starting router...\n");
  // input device number
  int device_number;
  printf("input device number: ");
  scanf("%d", &device_number);
  pcap_if_t* device = find_device_by_number(alldevsp, device_number);

  for (pcap_addr_t* address = device->addresses; address != NULL;
       address = address->next) {
    if (address->addr->sa_family == AF_INET) {
      host_ip = ((struct sockaddr_in*)address->addr)->sin_addr.s_addr;
      break;
    }
  }

  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t* handle = pcap_create(device->name, errbuf);

  if (handle == NULL) {
    fprintf(stderr, "error creating pcap handle: %s\n", errbuf);
  }

  pcap_set_promisc(handle, 1);
  pcap_set_snaplen(handle, 65535);
  pcap_set_timeout(handle, 1000);

  if (pcap_activate(handle) != 0) {
    fprintf(stderr, "error activating pcap handle: %s\n", pcap_geterr(handle));
  }

  get_host_mac(handle, host_ip, &host_mac);

  printf("[ router ] creating thread...\n");

  // start and detach
  HANDLE thread = CreateThread(
    NULL, 0, (LPTHREAD_START_ROUTINE)router_handler, (LPVOID)handle, 0, NULL
  );
}

void cli() {
  char command[256];

  // command be like: add dst mask hop
  // or: delete dst mask
  // or: show route
  // or: show arp
  // or: start

  printf("router >");
  while (scanf("%s", command) != EOF) {
    if (strcmp(command, "add") == 0) {
      ipv4_addr_t dst_ip;
      ipv4_addr_t mask;
      ipv4_addr_t next_hop_ip;

      uint32_t a, b, c, d;

      scanf("%u.%u.%u.%u", &a, &b, &c, &d);
      dst_ip = a | (b << 8) | (c << 16) | (d << 24);

      scanf("%u.%u.%u.%u", &a, &b, &c, &d);
      mask = a | (b << 8) | (c << 16) | (d << 24);

      scanf("%u.%u.%u.%u", &a, &b, &c, &d);
      next_hop_ip = a | (b << 8) | (c << 16) | (d << 24);

      route_entry_t* entry = route_table_alloc();
      entry->dst_ip = dst_ip;
      entry->mask = mask;
      entry->next_hop_ip = next_hop_ip;

      route_table_add(&route_table, entry);
    } else if (strcmp(command, "delete") == 0) {
      ipv4_addr_t dst_ip;
      ipv4_addr_t mask;

      uint32_t a, b, c, d;
      scanf("%u.%u.%u.%u", &a, &b, &c, &d);
      dst_ip = a | (b << 8) | (c << 16) | (d << 24);

      scanf("%u.%u.%u.%u", &a, &b, &c, &d);
      mask = a | (b << 8) | (c << 16) | (d << 24);

      route_entry_t* entry = route_table_find(&route_table, dst_ip, mask);
      
      if (entry != NULL) {
        route_table_remove(entry);
        route_table_free(entry);
      } else {
        printf("no such route entry\n");
      }
    } else if (strcmp(command, "show") == 0) {
      char subcommand[256];
      scanf("%s", subcommand);
      if (strcmp(subcommand, "route") == 0) {
        show_route_table();
      } else if (strcmp(subcommand, "arp") == 0) {
        show_arp_cache();
      }
    } else if (strcmp(command, "start") == 0) {
      running = true;
      start_routing();
    } else if (strcmp(command, "stop") == 0) {
      running = false;
    } else if (strcmp(command, "exit") == 0) {
      running = false;
      break;
    } else {
      printf("unknown command\n");
    }

    printf("router >");
  }
}