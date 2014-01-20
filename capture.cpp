#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <iostream>

using namespace std;

struct ethhdr *hdr_ether;
struct iphdr  *hdr_ip;
struct tcphdr *hdr_tcp;

void dumpData(unsigned char *data, int size) {
	char a, c;
	for(int i = 0; i < size; i++) {
		c = data[i];
		a = ( c >=32 && c <=128) ? (unsigned char) c : '.';
		printf("%c", a);
	}
	printf("\n\n");
}

bool findPassword(unsigned char *buffer, int size) {
	hdr_ether = (struct ethhdr*)buffer;
	int etherType = ((int)buffer[12] << 8) + buffer[13];
	buffer += ETH_HLEN;

	// IPv4
	if (etherType == 0x0800) {
		hdr_ip = (struct iphdr*)buffer;
		buffer += hdr_ip->ihl * 4;
		switch (hdr_ip->protocol) {
			// TCP
			case 0x06: {
				hdr_tcp = (struct tcphdr*)buffer;
				int len_hdr_tcp = hdr_tcp->doff * 4;

				// Port number
				int srcPort = ((int)buffer[0] << 8) + buffer[1];
				int desPort = ((int)buffer[2] << 8) + buffer[3];

				// IP address
				struct in_addr ip_addr_src, ip_addr_des;
				ip_addr_src.s_addr = hdr_ip->saddr;
				ip_addr_des.s_addr = hdr_ip->daddr;

				// Drop SSL packets
				if (srcPort != 443 || desPort != 443) {
					// Print address
					printf("%s:%d -> %s:%d\n",
						inet_ntoa(ip_addr_src), srcPort,
						inet_ntoa(ip_addr_src), desPort);

					// Print data
					buffer += len_hdr_tcp;
					dumpData(buffer, size - len_hdr_tcp);
				}
				break;
			}

			// UDP
			case 0x11:
				break;
		}
	}
	return true;
}

int main() {
	int sListen = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (sListen == -1) {
		cout << "Invalid socket" << endl;
		perror("listener: socket");
		return 0;
	}

	while (true) {
		unsigned char buffer[ETH_FRAME_LEN]; // buffer for ethernet frame
		int length = 0; // length of the received frame
		length = recvfrom(sListen, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
		if (length == -1) {
			// error handling
		} else {
			findPassword(buffer, length);
		}
	}

	close(sListen);

	return 0;
}
