#include "arp_support.h"

struct arp_entry *arp_table_root = NULL;

struct arp_entry *new_arp_entry() {
	struct arp_entry *entry = malloc(sizeof(struct arp_entry));

	if (!entry) {
		fprintf(stderr, "[ERROR] Couldn't alloc new ARP entry\n");
		exit(-1);
	}

	entry->status = ARP_ENTRY_WAITING;
	entry->packet_queue = queue_create();

	entry->left = NULL;
	entry->right = NULL;

	return entry;
}

void delete_arp_entry(struct arp_entry *entry) {
	if (!entry) return;

	// recursively free children first
	delete_arp_entry(entry->left);
	delete_arp_entry(entry->right);

	// now free this one
	free(entry);
}

struct arp_entry *add_arp_entry(struct in_addr nexthop) {
	struct arp_entry *new_entry = new_arp_entry();
	new_entry->nexthop = nexthop;

	// empty tree
	if (!arp_table_root) return (arp_table_root = new_entry);

	// binary search
	struct arp_entry *curr_entry = arp_table_root;

	while (curr_entry) {
		if (nexthop.s_addr > curr_entry->nexthop.s_addr) {
			// go right
			if (curr_entry->right) {
				// search here
				curr_entry = curr_entry->right;
			} else {
				// add here
				curr_entry->right = new_entry;
				break;
			}
		} else {
			// go left
			if (curr_entry->left) {
				curr_entry = curr_entry->left;
			} else {
				curr_entry->left = new_entry;
				break;
			}
		}
	}

	// return the added entry for future reference
	return new_entry;
}

struct arp_entry *get_arp_entry(struct in_addr nexthop) {
	struct arp_entry *curr_entry = arp_table_root;

	while (curr_entry) {
		// binary search
		if (nexthop.s_addr == curr_entry->nexthop.s_addr) {
			break;
		}

		if (nexthop.s_addr > curr_entry->nexthop.s_addr) {
			// go right
			curr_entry = curr_entry->right;
		} else {
			// go left
			curr_entry = curr_entry->left;
		}
	}

	return curr_entry;
}

void check_ARP_header(packet *m) {
	struct ether_arp *arphdr = PACK_ARP_HDR(m);

	switch (ntohs(arphdr->arp_op)) {
		case (ARPOP_REQUEST):
			// host requests a reply
			send_ARP_reply(m);
			break;
		case (ARPOP_REPLY):
			// received a response we previously requested
			; // C requires a statement after a label
			struct in_addr addr;
			memcpy(&(addr.s_addr), arphdr->arp_spa, 4);
			update_ARP_table(m, addr);
			break;
	}
}

void send_ARP_reply(packet *m) {
	struct ether_header *ethdr = PACK_ETH_HDR(m);
	struct ether_arp *arphdr = PACK_ARP_HDR(m);

	// prepare the reply
	packet reply;
	reply.len = LEN_ETH + LEN_ARP;
	memset(reply.payload, 0, MAX_LEN);
	reply.interface = m->interface;

	struct ether_header *reply_ethdr = PACK_ETH_HDR(&reply);
	struct ether_arp *reply_arphdr = PACK_ARP_HDR(&reply);

	// fill in the ethernet header
	memcpy(reply_ethdr->ether_dhost, ethdr->ether_shost, 6);

	// get the mac of the interface this packet came through
	get_interface_mac(m->interface, reply_ethdr->ether_shost);

	reply_ethdr->ether_type = htons(ETHERTYPE_ARP);

	// fill in the arp header
	reply_arphdr->arp_hrd = htons(ARPHRD_ETHER);
	reply_arphdr->arp_pro = htons(ETHERTYPE_IP);
	reply_arphdr->arp_hln = 6;
	reply_arphdr->arp_pln = 4;
	reply_arphdr->arp_op = htons(ARPOP_REPLY);
	memcpy(reply_arphdr->arp_sha, reply_ethdr->ether_shost, 6);
	memcpy(reply_arphdr->arp_spa, arphdr->arp_tpa, 4);
	memcpy(reply_arphdr->arp_tha, arphdr->arp_sha, 6);
	memcpy(reply_arphdr->arp_tpa, arphdr->arp_spa, 4);

	send_packet(reply.interface, &reply);
}

void send_ARP_request(int interface, struct in_addr nexthop) {
	// prepare the request
	packet request;
	request.len = LEN_ETH + LEN_ARP;
	memset(request.payload, 0, request.len);
	request.interface = interface;

	struct ether_header *request_ethdr = PACK_ETH_HDR(&request);
	struct ether_arp *request_arphdr = PACK_ARP_HDR(&request);

	// fill in the ethernet header

	// get the mac of the interface this packet will leave through
	get_interface_mac(interface, request_ethdr->ether_shost);

	// set broadcast
	memset(request_ethdr->ether_dhost, 0xff, 6);

	request_ethdr->ether_type = htons(ETHERTYPE_ARP);

	// fill in the arp header
	request_arphdr->arp_hrd = htons(ARPHRD_ETHER);
	request_arphdr->arp_pro = htons(ETHERTYPE_IP);
	request_arphdr->arp_hln = 6;
	request_arphdr->arp_pln = 4;
	request_arphdr->arp_op = htons(ARPOP_REQUEST);
	memcpy(request_arphdr->arp_sha, request_ethdr->ether_shost, 6);
	memcpy(request_arphdr->arp_tha, request_ethdr->ether_dhost, 6);

	uint32_t spa = get_interface_ip_uint32_t(request.interface);
	memcpy(request_arphdr->arp_spa, &spa, 4);

	memcpy(request_arphdr->arp_tpa, &(nexthop.s_addr), 4);

	send_packet(request.interface, &request);
}

void update_ARP_table(packet *m, struct in_addr addr) {
	struct ether_header *ethdr = PACK_ETH_HDR(m);
	
	// find an existent entry (will have the WAITING status)
	struct arp_entry *entry = get_arp_entry(addr);

	if (!entry) {
		// if it doesn't exist, create it
		entry = add_arp_entry(addr);
	}

	// register the mac address
	memcpy(entry->mac_addr, ethdr->ether_shost, 6);

	// set status
	entry->status = ARP_ENTRY_SET;

	while(!queue_empty(entry->packet_queue)) {
		// the packets waiting for this ARP request can now be forwarded
		forward((packet *) queue_deq(entry->packet_queue), entry->mac_addr);
	}
}

void delete_ARP_table() {
	delete_arp_entry(arp_table_root);
}