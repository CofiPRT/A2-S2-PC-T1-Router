#ifndef _ARP_SUPPORT_H_
#define _ARP_SUPPORT_H_

#include "skel.h"
#include "ip_support.h"
#include "queue.h"
#include "utils.h"

#define ARP_ENTRY_SET 1
#define ARP_ENTRY_WAITING 0

struct arp_entry {
	int status; // SET or WAITING
	queue packet_queue;

	struct in_addr nexthop;
	uint8_t mac_addr[6];

	// binary search tree
	struct arp_entry *left;
	struct arp_entry *right;
};

extern struct arp_entry *arp_table_root;

struct arp_entry *new_arp_entry();
void delete_arp_entry(struct arp_entry *entry);
struct arp_entry *add_arp_entry(struct in_addr nexthop);
struct arp_entry *get_arp_entry(struct in_addr nexthop);

void check_ARP_header(packet *m);
void send_ARP_reply(packet *m);
void send_ARP_request(int interface, struct in_addr nexthop);
void update_ARP_table(packet *m, struct in_addr addr);

void delete_ARP_table();

#endif