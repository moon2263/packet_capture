#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP 0x800
#define ETHERTYPE_ARP 0x806
struct ethernet{
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};	

struct ipH{
	u_char ip_header_len:4;
	u_char ip_version:4;
	u_char ip_tos;
	u_short ip_total_length;
	u_short ip_id;
	u_char ip_frag_offset:5;
	u_char ip_more_fragment:1;
	u_char ip_dont_fragment:1;
	u_char ip_reserved_zero:1;
	u_char ip_frag_offset1;
	u_char ip_ttl;
	u_char ip_protocal;
	u_short ip_checksum;
	struct in_addr ip_src,ip_dst;
};

struct tcp{
	uint16_t tcp_src;
	uint16_t tcp_dst;
	uint32_t tcp_seq_num;
	uint32_t tcp_ack_num;
	uint8_t tcp_res1:4;
	uint8_t tcp_hdr_len:4;
	uint8_t tcp_fin:1;
	uint8_t tcp_syn:1;
	uint8_t tcp_rst:1;
	uint8_t tcp_psh:1;
	uint8_t tcp_ack:1;
	uint8_t tcp_urg:1;
	uint8_t tcp_res2:2;
	uint16_t tcp_win_size;
	uint16_t tcp_chk;
	uint16_t tcp_urg_ptr;
};

u_int16_t show_ether_header(struct ethernet *);
u_char show_ip_header(struct ipH *);
u_int8_t show_tcp_header(struct tcp * );
void show_data(u_char *);
void print_mac_addr(u_char * mac_addr);

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		struct ethernet *ether_header;
		struct ipH * ip_header;
		struct tcp * tcp_header;
		int offset = 0;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		printf("%u bytes captured\n", header->caplen);
		ether_header = (struct ethernet*)(packet);
		if(show_ether_header(ether_header) == ETHERTYPE_IP)
		{
			ip_header = (struct ipH *)(packet+14);
			offset = ip_header->ip_header_len * 4;
			if(show_ip_header(ip_header) == IPPROTO_TCP)
			{		
				tcp_header = (struct tcp *)(ip_header+offset);
				offset = tcp_header->tcp_hdr_len * 4;
				show_tcp_header(tcp_header);
				if(offset > 0)
				{
					show_data((u_char *)(tcp_header+offset));
				}
			}
		}
	}

	pcap_close(handle);
	return 0;
}

u_int16_t show_ether_header(struct ethernet * ether)
{
	printf("[+] Source ADDR : "); print_mac_addr(ether->ether_shost);
	printf("[+] Dest ADDR : "); print_mac_addr(ether->ether_dhost);
	printf("[+] ETHER TYPE : 0x%x\n", ntohs(ether->ether_type));
	return ntohs(ether->ether_type);
}

void print_mac_addr(u_char * mac_addr)
{
	printf("[%02x:%02x:%02x:%02x:%02x:%02x]\n",
			mac_addr[0],
			mac_addr[1],
			mac_addr[2],
			mac_addr[3],
			mac_addr[4],
			mac_addr[5]);
}

u_char show_ip_header(struct ipH * ip_header)
{
	printf("[*] Source IP : %s\n", inet_ntoa(ip_header->ip_src));
	printf("[*] Dest IP : %s\n", inet_ntoa(ip_header->ip_dst));
	return ip_header->ip_protocal;
}

uint8_t show_tcp_header(struct tcp * tcp_header)
{
	printf("[-] Source Port : %d\n", ntohs(tcp_header->tcp_src));
	printf("[-] Dest Port :%d\n", ntohs(tcp_header->tcp_dst));
	return tcp_header->tcp_hdr_len;
}

void show_data(u_char * data)
{
	for(int i = 0;i<sizeof(data);i++)
	{
		if(i>16) break;
		printf("%02c ",data+i);
	}
	printf("\n");
}
