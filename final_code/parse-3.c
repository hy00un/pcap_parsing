#include <pcap.h>
#include <stdio.h>
	 pcap_t *handle;
     void packet_data(u_char *args, const struct pcap_pkthdr *header,const u_char *packet);

	 int main(int argc, char *argv[])
	 {
		char *dev;			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		char filter_exp[] = "port 80";	/* The filter expression */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr header;	/* The header that pcap gives us */
		const u_char *packet;		/* The actual packet */
        int cnt = 0;
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
		/* Find the properties for the device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			net = 0;
			mask = 0;
		}
		/* Open the session in promiscuous mode */
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return(2);
		}
		/* Compile and apply the filter */
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		/* Grab a packet */
        pcap_loop(handle,0,packet_data,NULL);
		pcap_close(handle);
	}

    void packet_data(u_char *args, const struct pcap_pkthdr *header,const u_char *packet) {
	    int S_ip[5]={0,}, D_ip[5]={0,}, S_port[3]={0,}, D_port[3]={0,};
        //if(packet == NULL || header->caplen == 0)
        printf("[*]Jacked a packet with length of [%d]\n", header->len);
        printf("[-]Destination mac : %02x:%02x:%02x:%02x:%02x:%02x\n", *(packet++), *(packet++), *(packet++), *(packet++), *(packet++), *(packet++));
        printf("[-]Source mac : %02x:%02x:%02x:%02x:%02x:%02x\n", *(packet++), *(packet++), *(packet++), *(packet++), *(packet++), *(packet++));
        packet+=14;
        S_ip[3] = (*packet++);
        S_ip[2] = (*packet++);
        S_ip[1] = (*packet++);
        S_ip[0] = (*packet++);
        printf("[-]Source IP : %02d.%02d.%02d.%02d\n", S_ip[0], S_ip[1], S_ip[2], S_ip[3]);
        D_ip[3] = (*packet++);
	    D_ip[2] = (*packet++);
	    D_ip[1] = (*packet++);
		D_ip[0] = (*packet++);
		printf("[-]Destination IP : %02d.%02d.%02d.%02d\n", D_ip[0], D_ip[1], D_ip[2], D_ip[3]);

        printf("[-]Source port : %02x:%02x\n", *(packet++), *(packet++));
        printf("[-]Destination port : %02x:%02x\n", *(packet++), *(packet++));
        printf("\n");
    }
