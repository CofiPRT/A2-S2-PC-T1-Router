#include "rtable.h"

struct rtable_entry *new_rtable_entry(struct in_addr nexthop, int interface) {
	struct rtable_entry *entry = malloc(sizeof(struct rtable_entry));

	if (!entry) {
		fprintf(stderr, "[ERROR] Couldn't alloc new RTABLE entry\n"
						"\tnexthop: %s\n"
						"\tinterface: %d\n",
							inet_ntoa(nexthop),
							interface);
		exit(-1);
	}

	entry->nexthop = nexthop;
	entry->interface = interface;

	return entry;
}

struct rtable_node *new_rtable_node() {
	struct rtable_node *node = malloc(sizeof(struct rtable_node));

	if (!node) {
		fprintf(stderr, "[ERROR] Couldn't alloc new RTABLE node\n");
		exit(-1);
	}

	node->entry = NULL;
	node->zero = NULL;
	node->one = NULL;

	return node;
}

void delete_rtable_node(struct rtable_node *node) {
	if (!node) return;

	// recursively free children first
	delete_rtable_node(node->zero);
	delete_rtable_node(node->one);

	// now free this one
	free(node->entry);
	free(node);
}

void add_rtable_entry(struct in_addr ip,
				struct in_addr nexthop,
				struct in_addr mask,
				int interface) {

	// convert to host byte order
	uint32_t ip_h = ntohl(ip.s_addr);
	uint32_t mask_h = ntohl(mask.s_addr);

	// start at the top of the trie
	struct rtable_node *curr_node = rtable_root;

	uint32_t curr_bit = (1 << 31);
	while (mask_h & curr_bit) {
		// we add as many bits as there are in mask

		// move to the zero or one child, according to this current bit in ip_h
		// create the child if necessary
		if (ip_h & curr_bit) {
			// it's one
			if (!curr_node->one) {
				// if it doesn't exist, create it
				curr_node->one = new_rtable_node();
			}

			// regardless, move to it
			curr_node = curr_node->one;
		} else {
			// it's zero
			if (!curr_node->zero) {
				curr_node->zero = new_rtable_node();
			}

			curr_node = curr_node->zero;
		}

		curr_bit >>= 1;
	}

	// we will link an entry to the last node that was reached
	if (!curr_node->entry) {
		// avoid duplicates
		curr_node->entry = new_rtable_entry(nexthop, interface);
	}
}

struct rtable_entry *get_rtable_entry(struct in_addr ip) {
	// printf("entered get_rtable_entry with %s\n", inet_ntoa(ip));

	// if it stays null, it hasn't been found
	struct rtable_entry *found_entry = NULL;

	// convert to host byte order
	uint32_t ip_h = ntohl(ip.s_addr);

	// start at the top of the trie
	struct rtable_node *curr_node = rtable_root;

	uint32_t curr_bit = (1 << 31);
	while (curr_node) {
		if (curr_node->entry) {
			// this node has an entry, and it's the farthest we found
			// save it
			found_entry = curr_node->entry;
		}

		// move through the adequate children
		if (ip_h & curr_bit) {
			// it's one
			curr_node = curr_node->one;
		} else {
			curr_node = curr_node->zero;
		}

		curr_bit >>= 1;
	}

	return found_entry;
}

void parse_rtable() {
	// open for reading
	FILE *in_file = fopen(RTABLE_FILE, "r");

	// initialize trie root
	rtable_root = new_rtable_node();

	char ip[RTABLE_STR_SIZE], nexthop[RTABLE_STR_SIZE], mask[RTABLE_STR_SIZE];
	struct in_addr ip_struct, nexthop_struct, mask_struct;
	int interface;

	while (fscanf(in_file, "%s %s %s %d\n",
							ip, nexthop, mask, &interface) != EOF) {
		
		inet_aton(ip, &ip_struct);
		inet_aton(nexthop, &nexthop_struct);
		inet_aton(mask, &mask_struct);

		add_rtable_entry(ip_struct, nexthop_struct, mask_struct, interface);
	}
}

void delete_rtable() {
	delete_rtable_node(rtable_root);
}