#include <iostream>
#include <cstdio>
#include <stdlib.h>
#include <limits.h>
#include <sys/time.h>                                             
#include <pcap.h>                                             
#include <unistd.h>                                           
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <utility>
#include <string.h>

#define ETH_HDR_LEN 14

using namespace std;

double getTime() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec + (double)tv.tv_usec / 1000000);
}

unsigned short in_cksum(unsigned short *addr, int len) {
	int nleft = len;
	unsigned short *w = addr;
	int sum = 0;
	unsigned short answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return (unsigned short)answer;
}

int main(int argc, char** argv) {
	pcap_t* pcap;
	char errbuf[256];
	struct pcap_pkthdr hdr;
	const u_char* pkt;
	double pkt_ts;
	int mode;
	unsigned long long int hh_thresh;
	unsigned int h_pscan_thresh;
	unsigned int v_pscan_thresh;
	int epoch;

	struct ether_header* eth_hdr = NULL;
	struct ip* ip_hdr = NULL;
	struct tcphdr* tcp_hdr = NULL;
	struct udphdr* udp_hdr = NULL;

	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned short src_port;
	unsigned short dst_port;

	double epoch_start = 0;
	double current_time = 0;

	unsigned int tot_packets = 0;
	unsigned int tot_ip_packets = 0;
	unsigned int tot_valid_ip_packets = 0;
	unsigned int tot_ip_payload_size = 0;
	unsigned int tot_tcp_packets = 0;
	unsigned int tot_udp_packets = 0;
	unsigned int tot_icmp_packets = 0;
	
	

	if (argc != 7) {
		fprintf(stderr, "Usage: %s "
						"<online/offline> "
						"<arg> "
						"<hh_thresh> "
						"<h_pscan_thresh> "
						"<v_pscan_thresh> "
						"<epoch>\n", argv[0]);
		exit(1);
	}

	if (strcmp(argv[1], "online") == 0) {
		mode = 1;
		if ((pcap = pcap_open_live(argv[2], 1500, 1, 1000, errbuf)) == NULL) {
			fprintf(stderr, "ERR: cannot open %s (%s)\n", argv[1], errbuf);
			exit(1);
		}
	}
	else if (strcmp(argv[1], "offline") == 0) {
		mode = 0;
		if ((pcap = pcap_open_offline(argv[2], errbuf)) == NULL) {
			fprintf(stderr, "ERR: cannot open %s (%s)\n", argv[1], errbuf);
			exit(1);
		}
	}
	

	hh_thresh = atoi(argv[3]);
	hh_thresh = hh_thresh * 1000000;
	h_pscan_thresh = atoi(argv[4]);
	v_pscan_thresh = atoi(argv[5]);
	epoch = atoi(argv[6]);

	unordered_map<unsigned int, unsigned int> byte;
	unordered_map<unsigned int, char> hh_status;
	map<pair<unsigned int, unsigned short>, unordered_set<unsigned int>> hpscan;
	map<pair<unsigned int, unsigned short>, char> hpscan_status;
	map<pair<unsigned int, unsigned int>, unordered_set<unsigned short>> vpscan;
	map<pair<unsigned int, unsigned int>, char> vpscan_status;

	while (1) {
		current_time = getTime();
		//printf("Current_time = %lf\n", current_time);
		if (epoch_start != 0 && current_time - epoch_start > epoch) {
			//print aggregate result
			printf("Total number of observed packets: %u\n", tot_packets);
			printf("Total number of observed IP packets: %u\n", tot_ip_packets);
			printf("Total number of observed valid IP packets: %u\n", tot_valid_ip_packets);
			printf("Total IP payload size: %u bytes\n", tot_ip_payload_size);
			printf("Total number of TCP packets: %u\n", tot_tcp_packets);
			printf("Total number of UDP packets: %u\n", tot_udp_packets);
			printf("Total number of ICMP packets: %u\n", tot_icmp_packets);

			byte.clear();
			hh_status.clear();
			hpscan.clear();
			hpscan_status.clear();
			vpscan.clear();
			vpscan_status.clear();
			tot_packets = 0;
			tot_ip_packets = 0;
			tot_valid_ip_packets = 0;
			tot_ip_payload_size = 0;
			tot_tcp_packets = 0;
			tot_udp_packets = 0;
			tot_icmp_packets = 0;
			epoch_start = current_time;
		}
		// capture packet, payload stored in pkt
		if ((pkt = pcap_next(pcap, &hdr)) != NULL) {
			tot_packets++;
			// get the timestamp from header
			pkt_ts = (double)hdr.ts.tv_usec / 1000000 + hdr.ts.tv_sec;

			if (epoch_start == 0)
				epoch_start = pkt_ts;

			// extract ethernet header
			eth_hdr = (struct ether_header*)pkt;

			// check ethernet's type, get ip header
			switch (ntohs(eth_hdr->ether_type)) {
				case ETH_P_IP:		// IP packets (no VLAN header)
					ip_hdr = (struct ip*)(pkt + ETH_HDR_LEN); 
					break;
				case 0x8100:		// with VLAN header (with 4 bytes)
					ip_hdr = (struct ip*)(pkt + ETH_HDR_LEN + 4); 
					break;
			}
			
			tot_ip_packets++;
			// if IP header is NULL (not IP or VLAN) or checksum invalid, continue.
			if (ip_hdr == NULL || in_cksum((unsigned short*)ip_hdr, ip_hdr->ip_hl << 2) != 0) {
				continue;
			}

			tot_valid_ip_packets++;


			// IP addresses are in network-byte order

			// get source ip and destination ip
			src_ip = ip_hdr->ip_src.s_addr;
			dst_ip = ip_hdr->ip_dst.s_addr;

			byte[src_ip] += ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl * 4;
			
			if (byte[src_ip] > hh_thresh && hh_status[src_ip] == 0) {
				printf("At timestamp %lf: A heavy hitter is detected\n"
						"- source IP: %d.%d.%d.%d\n",
						pkt_ts, src_ip & 0xff, (src_ip >> 8) & 0xff,
						(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff);
				hh_status[src_ip] = 1;
			}
			
			if (ip_hdr->ip_p == IPPROTO_ICMP) {
				tot_icmp_packets++;
			}
			else if (ip_hdr->ip_p == IPPROTO_TCP || ip_hdr->ip_p == IPPROTO_UDP){
				// if transport layer type == TCP
				if (ip_hdr->ip_p == IPPROTO_TCP) {
					// get tcp header, source port, destination port
					tcp_hdr = (struct tcphdr*)((u_char*)ip_hdr + 
							(ip_hdr->ip_hl << 2)); 
					src_port = ntohs(tcp_hdr->source);
					dst_port = ntohs(tcp_hdr->dest);
					tot_tcp_packets++;
				}
				else {
					tot_udp_packets++;
					udp_hdr = (struct udphdr*)((u_char*)ip_hdr + 
							(ip_hdr->ip_hl << 2));
					src_port = ntohs(udp_hdr->source);
					dst_port = ntohs(udp_hdr->dest);
				}

				pair<unsigned int, unsigned short> ip_port(src_ip, dst_port);
				hpscan[ip_port].insert(dst_ip);
				if (hpscan[ip_port].size() >= h_pscan_thresh &&
					hpscan_status[ip_port] == 0) {
					printf("At timestamp %lf: A horizontal portscan is detected\n"
							"- source IP: %d.%d.%d.%d, port: %hu\n",
							pkt_ts, src_ip & 0xff, (src_ip >> 8) & 0xff, 
							(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff, 
							dst_port);
					hpscan_status[ip_port] = 1;
				}

				pair<unsigned int, unsigned int> ip_ip(src_ip, dst_ip);
				vpscan[ip_ip].insert(dst_port);
				if (vpscan[ip_ip].size() >= v_pscan_thresh &&
					vpscan_status[ip_ip] == 0) {
					printf("At timestap %lf: A vertical portscan is dectected\n"
							"- source IP: %d.%d.%d.%d, target IP: %d.%d.%d.%d\n",
							pkt_ts, src_ip & 0xff, (src_ip >> 8) & 0xff,
							(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff,
							dst_ip & 0xff, (dst_ip >> 8) & 0xff,
							(dst_ip >> 16) & 0xff, (dst_ip >> 24) & 0xff);
					vpscan_status[ip_ip] = 1;
				}
			}
			//printf("protocol = %d\n", ip_hdr->ip_p);
			tot_ip_payload_size += ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl * 4;
			
		}
		else if (mode == 0) {
			break;
		}
			
	}
	pcap_close(pcap);
	return 0;
}
