#include <signal.h>

#include "skel.h"
#include "arp_support.h"
#include "ip_support.h"
#include "rtable.h"
#include "utils.h"

int main()
{
	packet m;
	int rc;

	init();

	init_signals();

	// read rtable.txt
	parse_rtable();

	while (1) {
		rc = get_packet(&m);

		if (rc < 0) {
			fprintf(stderr, "[ERROR] Error while getting packet\n");
			exit(-1);
		}

		struct ether_header *ethdr = (struct ether_header *) m.payload;

		switch (ntohs(ethdr->ether_type)) {
			case (ETHERTYPE_ARP):
				check_ARP_header(&m);
				break;
			case (ETHERTYPE_IP):
				check_IP_header(&m);
				break;
		}

	}
}