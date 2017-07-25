#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
#define ETHERTYPE_IP 0x0800
#define IPROTO_TCP 6

/* Ethernet header */
typedef struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
} SSS;

/* IP header */
struct sniff_ip {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
    u_char th_offx2;	/* data offset, rsvd */
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

#define SIZE_ETHERNET 14

const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ip *ip; /* The IP header */
const struct sniff_tcp *tcp; /* The TCP header */
const char *data; /* Packet payload */

int main(int argc, char* argv[]) {
    char buf[20];
    char buf2[20];
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    int packet;
    SSS *ethernet;
    const u_char *pkt_data;
    if(argv[1] == NULL) {
        printf("Input Interface name\n");
        return 0;
    }
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL) {
        fprintf(stderr, "Couldn't open deivce %s : %s",argv[1],errbuf);
        return 0;
    }

    while(1) {
        packet = pcap_next_ex(handle, &header, &pkt_data);
        if(packet == -1 || packet == -2)
            break;
        if(packet == 0)
        {
            continue;
        }
        ethernet = (struct sniff_ethernet*)(pkt_data);
        ip = (struct sniff_ip*)(pkt_data+SIZE_ETHERNET);
        tcp = (struct sniff_tcp*)(pkt_data+SIZE_ETHERNET+IP_HL(ip)*4);
        data = (char*)(pkt_data+SIZE_ETHERNET+IP_HL(ip)*4+TH_OFF(tcp)*4);
        //printf("%02x\n\n",ntohs(ip->ip_len));
        //printf("%x\n\n",ethernet->ether_type);:q
        //if(tcp->th_sport!=80 || tcp->th_dport!=80) continue;

        //if(ethernet->ip_p == IPPROTO_TCP)
        if(ip->ip_p != IPPROTO_TCP) continue;
        if(ntohs(tcp->th_sport)!= 0x50 && ntohs(tcp->th_dport)!=0x50) continue;
        //if(data[0]==0 && data[1]==0) continue;
        if(ntohs(ethernet->ether_type)==ETHERTYPE_IP) {
            printf("[-]destination mac : ");
            for(int i=0; i<=5; i++)
                printf("%02x ",(ethernet->ether_dhost[i]));
            printf("\n");
            printf("[-]source mac : ");
            for(int i=0; i<=5; i++)
                printf("%02x ",(ethernet->ether_shost[i]));
            printf("\n");
            //printf("destination ip : %s\n",inet_ntoa(ip->ip_dst));
            //printf("source ip : %s\n",inet_ntoa(ip->ip_src));
            inet_ntop(AF_INET,(&ip->ip_dst),buf,sizeof(buf));
            inet_ntop(AF_INET,(&ip->ip_src),buf2,sizeof(buf2));
            printf("[-]destination ip : %s\n",buf);
            printf("[-]source ip : %s\n",buf2);
            printf("[-]source port : %d\n",ntohs(tcp->th_sport));
            printf("[-]destination port : %d\n",ntohs(tcp->th_dport));
            printf("======================DATA======================\n");
            if(ntohs(ip->ip_len) - IP_HL(ip)*4 - TH_OFF(tcp)*4 == 0) {
                printf("NO DATA\n\n");
                continue;
            }
            int TCP_DATA_SIZE = (header->len)-(SIZE_ETHERNET+IP_HL(ip)*4+TH_OFF(tcp)*4);
            for(int i=1; i<=TCP_DATA_SIZE; i++) {
                printf("%02x ",data[i-1]);
                if(i%16==0)
                    printf("\n");
            }
            printf("\n\n");
        }
        //printf("");
        //printf("%s ",ip->ip_src);
        //printf("%s",buf);
        ///printf("%x",(ethernet->ether_dhost));
        ///printf("%x",(ethernet->ether_shost));
        //for(int i=0;i<25;i++)
        //    printf("%02x ",pkt_data[i]); // test data
        //printf("%d",header->len);
    }
    pcap_close(handle);
}
