#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP 0x800
#define ETHERTYPE_ARP 0x806
#define ETHER_IP_OFFSET 14
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
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	u_int th_seq;		/* sequence number */
	u_int th_ack;		/* acknowledgement number */
	u_char th_off;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

u_int16_t show_ether_header(struct ethernet *);
u_char show_ip_header(struct ipH *);
u_int8_t show_tcp_header(struct tcp * );
void show_data(u_char *,int,int,int);
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
		int total_len = 0, ip_tcp_offset = 0, tcp_data_offset = 0;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		printf("%u bytes captured\n", header->caplen);
		ether_header = (struct ethernet*)(packet);
		if(show_ether_header(ether_header) == ETHERTYPE_IP)
		{
			ip_header = (struct ipH *)(packet+ETHER_IP_OFFSET);
			ip_tcp_offset = ip_header->ip_header_len * 4;
			total_len = ip_header->ip_total_length;
			if(show_ip_header(ip_header) == IPPROTO_TCP)
			{		
				tcp_header = (struct tcp *)((u_char *)ip_header+ip_tcp_offset);
				tcp_data_offset = tcp_header->th_off * 4;
				show_tcp_header(tcp_header);
				if(tcp_data_offset > 0)
				{
					show_data((u_char *)tcp_header+tcp_data_offset,total_len,ip_tcp_offset,tcp_data_offset);
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
	printf("[-] Source Port : %d\n", ntohs(tcp_header->th_sport));
	printf("[-] Dest Port :%d\n", ntohs(tcp_header->th_dport));
	return tcp_header->th_off;
}

void show_data(u_char * data,int total_len,int ip_tcp_offset,int tcp_data_offset)
{
	int size = total_len-ETHER_IP_OFFSET-ip_tcp_offset-tcp_data_offset;
	for(int i = 0;i<size;i++)
	{
		if(i>16) break;
		printf("%c ",data[i]);
	}
	printf("\n");
}
