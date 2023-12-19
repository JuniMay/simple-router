#include <stdbool.h>
#include <stdint.h>

#include <pcap/pcap.h>

/// An intrusive doubly-linked list.
typedef struct _list_entry {
  struct _list_entry *prev, *next;
} list_entry_t;

#define offset_of(type, member) ((size_t)(&((type*)0)->member))

#define container_of(ptr, type, member) \
  ((type*)((char*)(ptr)-offset_of(type, member)))

#define FOR_EACH_ENTRY(entry, list, type, member)        \
  for (entry = container_of((list)->next, type, member); \
       &entry->member != (list);                         \
       entry = container_of(entry->member.next, type, member))

static inline void list_init(list_entry_t* elm) {
  elm->prev = elm->next = elm;
}

static inline void list_add(list_entry_t* listelm, list_entry_t* elm) {
  listelm->next->prev = elm;
  elm->next = listelm->next;
  listelm->next = elm;
  elm->prev = listelm;
}

static inline void list_add_after(list_entry_t* listelm, list_entry_t* elm) {
  list_add(listelm, elm);
}

static inline void list_add_before(list_entry_t* listelm, list_entry_t* elm) {
  list_add(listelm->prev, elm);
}

static inline void list_del(list_entry_t* listelm) {
  listelm->prev->next = listelm->next;
  listelm->next->prev = listelm->prev;
}

static inline int list_empty(list_entry_t* list) {
  return list->next == list;
}

typedef struct _mac_addr {
  uint8_t addr[6];
} mac_addr_t;

typedef uint32_t ipv4_addr_t;

/// Ethernet header, 14 octets.
typedef struct _ether_hdr {
  /// Destination MAC address
  mac_addr_t dst_mac;
  /// Source MAC address
  mac_addr_t src_mac;
  /// Ether type or length
  uint16_t ether_type;
} ether_hdr_t;

/// ARP header, 28 octets.
#pragma pack(push, 1)
typedef struct _arp_packet {
  /// Hardware type
  uint16_t hardware_type;
  /// Protocol type
  uint16_t protocol_type;
  /// Langth of MAC address
  uint8_t mac_addr_len;
  /// Length of IP address
  uint8_t ip_addr_len;
  /// Operation
  uint16_t operation;
  /// Sender MAC address
  mac_addr_t sender_mac;
  /// Sender IP address
  ipv4_addr_t sender_ip;
  /// Target MAC address
  mac_addr_t target_mac;
  /// Target IP address
  ipv4_addr_t target_ip;
} arp_packet_t;

/// Ethernet type for IPv4
#define ETHER_TYPE_IPV4 0x0800

/// Ethernet type for ARP
#define ETHER_TYPE_ARP 0x0806

#define ARP_HARDWARE_TYPE_ETHERNET 0x0001

#define ARP_OPERATION_REQUEST 0x0001
#define ARP_OPERATION_REPLY 0x0002

/// IPv4 header, 20 octets.
///
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Ver  |  IHL  |   DSCP    |ECN|          Total Length         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Identification        |Flags|      Fragment Offset    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Time to Live |    Protocol   |        Header Checksum        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Source Address                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Destination Address                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// Most significant byte first.
typedef struct _ipv4_hdr {
  /// Internet header length
  uint8_t ihl : 4;
  /// Version
  uint8_t version : 4;
  /// Type of service, ECN
  uint8_t ecn : 2;
  /// Type of service, DSCP
  uint8_t dscp : 6;
  /// Total length
  uint16_t total_length;
  /// Identification
  uint16_t identification;
  /// Flags and fragmentation offset
  uint16_t fragmentation;
  /// Time to live
  uint8_t ttl;
  /// Protocol
  uint8_t protocol;
  /// Header checksum
  uint16_t checksum;
  /// Source address
  ipv4_addr_t src_addr;
  /// Destination address
  ipv4_addr_t dst_addr;
} ipv4_hdr_t;

void send_arp_request(
  pcap_t* handle,
  ipv4_addr_t src_ip,
  const mac_addr_t* src_mac,
  ipv4_addr_t dst_ip
);

int listen_arp_reply(
  pcap_t* handle,
  ipv4_addr_t expected_ip,
  mac_addr_t* out_mac
);

int get_host_mac(pcap_t* handle, ipv4_addr_t host_ip, mac_addr_t* out_mac);

int get_remote_mac(
  pcap_t* handle,
  ipv4_addr_t src_ip,
  const mac_addr_t* src_mac,
  ipv4_addr_t dst_ip,
  mac_addr_t* out_mac
);

/// An ARP cache entry.
typedef struct _arp_entry {
  /// The IP address of the host.
  ipv4_addr_t ip;
  /// The MAC address of the host.
  mac_addr_t mac;
  /// The next entry in the list.
  list_entry_t link;
} arp_entry_t;

/// The ARP cache.
typedef struct _arp_cache {
  /// The list of entries.
  list_entry_t entries;
} arp_cache_t;

/// Initialize the ARP cache.
static inline void arp_cache_init(arp_cache_t* cache) {
  list_init(&cache->entries);
}

/// Add an entry to the ARP cache.
static inline void arp_cache_add(arp_cache_t* cache, arp_entry_t* entry) {
  list_add(&cache->entries, &entry->link);
}

/// Remove an entry from the ARP cache.
static inline void arp_cache_remove(arp_entry_t* entry) {
  list_del(&entry->link);
}

/// Find an entry in the ARP cache.
static inline arp_entry_t* arp_cache_find(arp_cache_t* cache, ipv4_addr_t ip) {
  list_entry_t* entry;
  for (entry = cache->entries.next; entry != &cache->entries;
       entry = entry->next) {
    arp_entry_t* arp_entry = container_of(entry, arp_entry_t, link);
    if (arp_entry->ip == ip) {
      return arp_entry;
    }
  }
  return NULL;
}

/// allocate an arp entry
static inline arp_entry_t* arp_cache_alloc() {
  return (arp_entry_t*)malloc(sizeof(arp_entry_t));
}

/// free an arp entry
static inline void arp_cache_free(arp_entry_t* entry) {
  free(entry);
}

/// free all arp entries
static inline void arp_cache_free_all(arp_cache_t* cache) {
  list_entry_t* entry;
  for (entry = cache->entries.next; entry != &cache->entries;) {
    list_entry_t* next = entry->next;
    arp_entry_t* arp_entry = container_of(entry, arp_entry_t, link);
    arp_cache_free(arp_entry);
    entry = next;
  }
}

/// Route table entry.
typedef struct _route_entry {
  /// The destination IP address.
  ipv4_addr_t dst_ip;
  /// The subnet mask.
  ipv4_addr_t mask;
  /// The next hop IP address.
  ipv4_addr_t next_hop_ip;
  
  bool is_direct;

  /// The list link
  list_entry_t link;
} route_entry_t;

/// The route table.
typedef struct _route_table {
  /// The list of entries.
  list_entry_t entries;
} route_table_t;

/// Initialize the route table.
static inline void route_table_init(route_table_t* table) {
  list_init(&table->entries);
}

/// Add an entry to the route table.
static inline void route_table_add(route_table_t* table, route_entry_t* entry) {
  list_add(&table->entries, &entry->link);
}

/// Remove an entry from the route table.
static inline void route_table_remove(route_entry_t* entry) {
  list_del(&entry->link);
}

/// Find an entry in the route table.
static inline route_entry_t*
route_table_find(route_table_t* table, ipv4_addr_t ip, ipv4_addr_t mask) {
  list_entry_t* entry;
  for (entry = table->entries.next; entry != &table->entries;
       entry = entry->next) {
    route_entry_t* route_entry = container_of(entry, route_entry_t, link);
    if (route_entry->dst_ip == ip && route_entry->mask == mask) {
      return route_entry;
    }
  }
  return NULL;
}

/// Longest prefix match
static inline route_entry_t*
route_table_match(route_table_t* table, ipv4_addr_t ip) {
  list_entry_t* entry;
  route_entry_t* match = NULL;
  for (entry = table->entries.next; entry != &table->entries;
       entry = entry->next) {
    route_entry_t* route_entry = container_of(entry, route_entry_t, link);
    if ((ip & route_entry->mask) == route_entry->dst_ip) {
      if (match == NULL || route_entry->mask > match->mask) {
        match = route_entry;
      }
    }
  }
  return match;
}

/// allocate a route entry
static inline route_entry_t* route_table_alloc() {
  route_entry_t* entry = (route_entry_t*)malloc(sizeof(route_entry_t));
  entry->is_direct = false;
  return entry;
}

static inline void show_route_entry(route_entry_t* entry) {
  printf(
    "dst: %u.%u.%u.%u mask: %u.%u.%u.%u gw: %u.%u.%u.%u\n",
    entry->dst_ip & 0xff, (entry->dst_ip >> 8) & 0xff,
    (entry->dst_ip >> 16) & 0xff, (entry->dst_ip >> 24) & 0xff,
    entry->mask & 0xff, (entry->mask >> 8) & 0xff, (entry->mask >> 16) & 0xff,
    (entry->mask >> 24) & 0xff, entry->next_hop_ip & 0xff,
    (entry->next_hop_ip >> 8) & 0xff, (entry->next_hop_ip >> 16) & 0xff,
    (entry->next_hop_ip >> 24) & 0xff
  );
}

/// free a route entry
static inline void route_table_free(route_entry_t* entry) {
  free(entry);
}

/// free all route entries
static inline void route_table_free_all(route_table_t* table) {
  list_entry_t* entry;
  for (entry = table->entries.next; entry != &table->entries;) {
    list_entry_t* next = entry->next;
    route_entry_t* route_entry = container_of(entry, route_entry_t, link);
    route_table_free(route_entry);
    entry = next;
  }
}

int find_all_devices(pcap_if_t** alldevsp);

void free_all_devices(pcap_if_t* alldevsp);

void show_all_devices(pcap_if_t* alldevsp);

pcap_if_t* find_device_by_number(pcap_if_t* alldevsp, int number);

extern arp_cache_t arp_cache;
extern route_table_t route_table;
extern bool running;
extern pcap_if_t* alldevsp;
extern mac_addr_t host_mac;
extern ipv4_addr_t host_ip;

void show_mac_addr(mac_addr_t mac);

void show_arp_cache();

void show_route_table();

void cli();

void router_handler(pcap_t* handle);

void start_routing();

static bool check_checksum(ipv4_hdr_t* ipv4_hdr) {
  size_t size = ipv4_hdr->ihl;
  printf("size: %d\n", size);

  uint16_t* ptr = (uint16_t*)ipv4_hdr;
  uint32_t sum = 0;

  while (size > 1) {
    sum += *ptr;
    ptr++;
    size--;
  }

  if (size == 1) {
    sum += *(uint8_t*)ptr;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  return (uint16_t)~sum == 0;
}