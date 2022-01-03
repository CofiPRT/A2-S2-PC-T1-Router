#include "ip_support.h"

char validate_IP_checksum(struct iphdr *ip_hdr) {
	// save before resetting
	uint16_t ip_checksum = ip_hdr->check;

	// reset to 0 in order to recalculate
	ip_hdr->check = 0;

	if (checksum((void*) ip_hdr, LEN_IP) != ip_checksum) {
		// wrong checksum
		return 0;
	}

	// restore checksum
	ip_hdr->check = ip_checksum;

	return 1;
}

char validate_ICMP_checksum(struct icmphdr *icmp_hdr) {
	// save before resetting
	uint16_t icmp_checksum = icmp_hdr->checksum;

	// reset to 0 in order to recalculate
	icmp_hdr->checksum = 0;

	uint16_t new_icmp = checksum((void*) icmp_hdr, LEN_ICMP);

	printf("OLD: %x, NEW: %x\n", icmp_checksum, new_icmp);

	if (checksum((void*) icmp_hdr, LEN_ICMP) != icmp_checksum) {
		// wrong checksum
		return 0;
	}

	// restore checksum
	icmp_hdr->checksum = icmp_checksum;

	return 1;
}

void check_IP_header(packet *m) {
	struct iphdr *ip_hdr = PACK_IP_HDR(m);
	struct icmphdr *icmp_hdr = NULL;

	if (ip_hdr->protocol == IPPROTO_ICMP) {
		icmp_hdr = PACK_ICMP_HDR(m);
	}

	printf("received ip packet\n");

	if (ip_hdr->ttl <= 1) {
		// decrementing will lead to TTL = 0
		// (or even lower depending on the initial TTL)

		// time exceeded, notify sender
		send_ICMP_reply(m, ICMP_TIME_EXCEEDED);

		// drop this packet
		return;
	}

	printf("ttl is good\n");

	if (!validate_IP_checksum(ip_hdr)) {
		// wrong checksum, drop this packet
		return;
	}

	printf("ip check is good\n");

	// do the same thing for the ICMP header (ONLY if present)
	// if (icmp_hdr && !validate_ICMP_checksum(icmp_hdr)) {
	// 	return;
	// }

	printf("icmp check is good\n");

	if (get_interface_ip_uint32_t(m->interface) == ip_hdr->daddr &&
		icmp_hdr &&
		icmp_hdr->type == ICMP_ECHO) {
		// the router is the destination and an echo reply is requested
		send_ICMP_reply(m, ICMP_ECHOREPLY);

		// drop this packet
		return;
	}

	// find nexthop
	struct in_addr daddr;
	daddr.s_addr = ip_hdr->daddr;
	struct rtable_entry *rtentry = get_rtable_entry(daddr);
	printf("is dest unreach?\n");

	if (!rtentry) {
		// destination unreachable, notify sender
		printf("dest unreach\n");
		send_ICMP_reply(m, ICMP_DEST_UNREACH);

		// drop this packet
		return;
	}

	// we only need to modify the interface in order to get the info we need
	// for future forwarding
	m->interface = rtentry->interface;

	// so far so good, now the packet may be forwarded
	struct arp_entry *arpentry = get_arp_entry(rtentry->nexthop);
	if (!arpentry) {
		// no match for this nexthop in the ARP table, send a request
		send_ARP_request(rtentry->interface, rtentry->nexthop);

		// create a WAITING entry in the ARP table (to avoid multiple requests)
		struct arp_entry *new_arpentry = add_arp_entry(rtentry->nexthop);

		// this packet is now waiting for an ARP response for this entry
		packet *copy = malloc(sizeof(packet));
		memcpy(copy, m, sizeof(packet));
		queue_enq(new_arpentry->packet_queue, (void*) copy);
	} else if (arpentry->status == ARP_ENTRY_WAITING) {
		// ARP request previously sent but not yet received, enqueue this packet
		packet *copy = malloc(sizeof(packet));
		memcpy(copy, m, sizeof(packet));
		queue_enq(arpentry->packet_queue, (void*) copy);
	} else {
		// mac address is present, the packet will be forwarded
		forward(m, arpentry->mac_addr);
	}
}

void send_ICMP_reply(packet *m, uint8_t type) {
	struct ether_header *ethdr = PACK_ETH_HDR(m);
	struct iphdr *ip_hdr = PACK_IP_HDR(m);

	// prepare the reply
	packet reply;

	if (type == ICMP_ECHOREPLY) {
		reply.len = m->len;
		memcpy(reply.payload, m->payload, reply.len);
	} else {
		reply.len = m->len + LEN_IP + LEN_ICMP;
		memset(reply.payload, 0, reply.len);
	}

	reply.interface = m->interface;

	// fill in the ethernet header
	struct ether_header *reply_ethdr = PACK_ETH_HDR(&reply);

	memcpy(reply_ethdr->ether_dhost, ethdr->ether_shost, 6);
	memcpy(reply_ethdr->ether_shost, ethdr->ether_dhost, 6);
	reply_ethdr->ether_type = htons(ETHERTYPE_IP);

	// fill in the ip header
	struct iphdr *reply_ip_hdr = PACK_IP_HDR(&reply);

	if (type != ICMP_ECHOREPLY) {
		reply_ip_hdr->tot_len = htons(reply.len - LEN_ETH);
		reply_ip_hdr->version = 4;
		reply_ip_hdr->ihl = 5;
		reply_ip_hdr->protocol = IPPROTO_ICMP;
	}
	
	reply_ip_hdr->ttl = 255;
	reply_ip_hdr->saddr = get_interface_ip_uint32_t(m->interface);
	reply_ip_hdr->daddr = ip_hdr->saddr;

	// calculate checksum
	reply_ip_hdr->check = 0;
	reply_ip_hdr->check = checksum((void*) reply_ip_hdr, LEN_IP);

	// fill in the icmp header
	struct icmphdr *reply_icmp_hdr = PACK_ICMP_HDR(&reply);

	reply_icmp_hdr->type = type;

	if (type != ICMP_ECHOREPLY) {
		memcpy(PACK_ICMP_DATA(&reply), ip_hdr, m->len - LEN_ETH);
	}

	// calculate checksum
	reply_icmp_hdr->checksum = 0;
	reply_icmp_hdr->checksum = checksum((void*) reply_icmp_hdr, LEN_ICMP);

	send_packet(reply.interface, &reply);
}

void forward(packet *m, uint8_t mac_addr[6]) {
	struct ether_header *ethdr = PACK_ETH_HDR(m);
	struct iphdr *ip_hdr = PACK_IP_HDR(m);

	// fill in the ethernet header
	get_interface_mac(m->interface, ethdr->ether_shost);

	memcpy(ethdr->ether_dhost, mac_addr, 6);

	/* update the checksum according to RFC 1624

		due to the TTL being the ONLY changed field,
		this is also valid: (ip_hdr->check)++

		for the sake of the task, we'll do it by the book
	*/

	// we need a 16-bit value
	uint16_t value = ip_hdr->ttl;

	(ip_hdr->ttl)--;

	uint16_t new_value = ip_hdr->ttl;

	// keep endianness
	value = ntohs(value);
	new_value = ntohs(new_value);

	uint16_t check = ntohs(ip_hdr->check);
	uint32_t new_check = ~(~check + ~value + new_value);

	// because we are doing one's complement addition, add the carry bit
	// (this is the reason new_check is 32-bits long)
	ip_hdr->check = htons(new_check + (new_check>>16) - 1);

	send_packet(m->interface, m);
}