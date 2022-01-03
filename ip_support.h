#ifndef _IP_SUPPORT_H_
#define _IP_SUPPORT_H_

#include "skel.h"
#include "arp_support.h"
#include "rtable.h"

char validate_IP_checksum(struct iphdr *ip_hdr);
char validate_ICMP_checksum(struct icmphdr *icmp_hdr);

void check_IP_header(packet *m);
void send_ICMP_reply(packet *m, uint8_t type);

void forward(packet *m, uint8_t mac_addr[6]);

#endif