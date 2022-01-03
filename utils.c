#include "utils.h"

uint32_t get_interface_ip_uint32_t(int interface) {
	struct ifreq ifr;
	sprintf(ifr.ifr_name, "r-%u", interface);
	ioctl(interfaces[interface], SIOCGIFADDR, &ifr);
	return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
}

uint16_t checksum(void *vdata, size_t length) {
	// Cast the data pointer to one that can be indexed.
	char* data=(char*)vdata;

	// Initialise the accumulator.
	uint64_t acc=0xffff;

	// Handle any partial block at the start of the data.
	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	// Handle any complete 32-bit blocks.
	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;

	// Handle any partial block at the end of the data.
	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}

	// Handle deferred carries.
	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}

	// If the data began at an odd byte address
	// then reverse the byte order to compensate.
	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}

	// Return the checksum in network byte order.

	return htons(~acc);
}

void exit_gracefully(int sig) {
	delete_rtable();
	delete_ARP_table();

	printf("\nReceived signal: ");
	switch (sig) {
		case (SIGINT):
			printf("SIGINT\n");
			break;
		case (SIGSEGV):
			printf("SIGSEGV\n");
			break;
		case (SIGILL):
			printf("SIGILL\n");
			break;
	}
}

void init_signals() {
	signal(SIGINT, exit_gracefully);
	signal(SIGSEGV, exit_gracefully);
	signal(SIGILL, exit_gracefully);
}