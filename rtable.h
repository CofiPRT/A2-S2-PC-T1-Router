#ifndef _RTABLE_H_
#define _RTABLE_H_

#include "skel.h"

#define RTABLE_FILE "rtable.txt"
#define RTABLE_STR_SIZE 20 // just for alloc-ing strings

struct rtable_entry {
	struct in_addr nexthop;
	int interface;
};

struct rtable_entry *new_rtable_entry(struct in_addr nexthop, int interface);

struct rtable_node {
	struct rtable_entry *entry;

	struct rtable_node *zero;
	struct rtable_node *one;
};

struct rtable_node *rtable_root;

struct rtable_node *new_rtable_node();
void delete_rtable_node(struct rtable_node *node);
void add_rtable_entry(struct in_addr ip,
				struct in_addr nexthop,
				struct in_addr mask,
				int interface);
struct rtable_entry *get_rtable_entry(struct in_addr ip);

void parse_rtable();
void delete_rtable();

#endif