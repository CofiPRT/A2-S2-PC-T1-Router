#ifndef _UTILS_H_
#define _UTILS_H_

#include "skel.h"
#include "ip_support.h"
#include "arp_support.h"

#define LEN_ETH (sizeof(struct ether_header))
#define LEN_ARP (sizeof(struct ether_arp))
#define LEN_IP (sizeof(struct iphdr))
#define LEN_ICMP (sizeof(struct icmphdr))

#define LEN_IP_START (LEN_ETH)
#define LEN_ARP_START (LEN_ETH)
#define LEN_ICMP_START (LEN_ETH + LEN_IP)
#define LEN_ICMP_DATA_START (LEN_ICMP_START + LEN_ICMP)

#define PACK_ETH_HDR(m) ((struct ether_header *) (((packet*)m)->payload))
#define PACK_ARP_HDR(m) ((struct ether_arp *) (((packet*)m)->payload + LEN_ARP_START))
#define PACK_IP_HDR(m) ((struct iphdr *) (((packet*)m)->payload + LEN_IP_START))
#define PACK_ICMP_HDR(m) ((struct icmphdr *) (((packet*)m)->payload + LEN_ICMP_START))
#define PACK_ICMP_DATA(m) ((void*) (((packet*)m)->payload + LEN_ICMP_DATA_START))

uint32_t get_interface_ip_uint32_t(int interface);
uint16_t checksum(void *vdata, size_t length);

void exit_gracefully(int sig);
void init_signals();

#endif