#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define  PROMISCUOUS 1

struct   iphdr    *iph;
struct   tcphdr   *tcph;
struct   udphdr   *udph;
struct   icmp     *icmph;
static   pcap_t   *pd;
int sockfd;
int pflag;
int rflag;
int eflag;
int cflag;
int chcnt;

char    *device, *filter_rule;

void packet_analysis(unsigned char *, const struct pcap_pkthdr *, 
                    const unsigned char *);

struct printer {
   pcap_handler f;
   int type;
};
   

static struct printer printers[] = {
   { packet_analysis, DLT_IEEE802 },
   { packet_analysis, DLT_EN10MB  },
   { NULL, 0 },
};
   
static pcap_handler lookup_printer(int type) 
{
	struct printer *p;

	for(p=printers; p->f; ++p)
		if(type == p->type)
			return p->f;
			
	perror("unknown data link type");
}

void packet_analysis(unsigned char *user, const struct pcap_pkthdr *h, 
                    const unsigned char *p)
{
	int j, temp;
	unsigned int length = h->len;
	struct ether_header *ep;
	unsigned short ether_type;
	unsigned char *tcpdata, *udpdata,*icmpdata, temp_char;
	register unsigned int i;
	
	chcnt = 0;
	
	if(rflag) {
		while(length--) {
			printf("%02x ", *(p++));
			if( (++chcnt % 16) == 0 ) printf("\n");
		}
		fprintf(stdout, "\n");
		return;
	}

	length -= sizeof(struct ether_header);
	
	// ethernet header mapping
	ep = (struct ether_header *)p;
	// ethernet header만큼 띄우기.
	p += sizeof(struct ether_header);
	// datalink type
	ether_type = ntohs(ep->ether_type);
	
	printf("\n");
	// Ethernet frame이 802인경우 ether_type필드가 길이필드가 된다.
	if(ether_type <= 1500) {
		while(length--) {
			if(++is_llchdr <= 3) {
				fprintf(stdout,"%02x",*p++);
				continue;
			}
			if(++next_line == 16) {
				next_line = 0;      
				printf("\n");
			}
			printf("%02x",*p++);
		}
	}
	else 
	{    
		if(eflag) {
			printf("\n\n=================== Datalink layer ===================\n");
			for(j=0; j<ETH_ALEN; j++) {
				printf("%X", ep->ether_shost[j]);
						if(j != 5) printf(":");
			}       
			printf("  ------> ");
			for(j=0; j<ETH_ALEN; j++){ 
				printf("%X", ep->ether_dhost[j]); 
				if(j != 5) printf(":");
			}
			printf("\nether_type -> %x\n", ntohs(ep->ether_type));
		}

		iph = (struct iphdr *) p;
		i = 0;
		if (ntohs(ep->ether_type) == ETHERTYPE_IP) {        // ip 패킷인가?
			printf("\n\n===================    IP HEADER   ===================\n");
			printf("%s -----> ",   inet_ntoa(iph->saddr));
			printf("%s\n", inet_ntoa(iph->daddr));
			printf("Version:         %d\n", iph->version);
			printf("Herder Length:   %d\n", iph->ihl);
			printf("Service:         %#x\n",iph->tos);
			printf("Total Length:    %d\n", ntohs(iph->tot_len)); 
			printf("Identification : %d\n", ntohs(iph->id));
			printf("Fragment Offset: %d\n", ntohs(iph->frag_off)); 
			printf("Time to Live:    %d\n", iph->ttl);
			printf("Checksum:        %d\n", ntohs(iph->check));
	
			if(iph->protocol == IPPROTO_TCP) {
				tcph = (struct tcphdr *) (p + iph->ihl * 4);
				// tcp data는 
				tcpdata = (unsigned char *) (p + (iph->ihl*4) + (tcph->doff * 4));
				printf("\n\n===================   TCP HEADER   ===================\n");
				printf("Source Port:              %d\n", ntohs(tcph->source));
				printf("Destination Port:         %d\n", ntohs(tcph->dest));
				printf("Sequence Number:          %d\n", ntohl(tcph->seq));
				printf("Acknowledgement Number:   %d\n", ntohl(tcph->ack_seq));
				printf("Data Offset:              %d\n", tcph->doff);
				printf("Window:                   %d\n", ntohs(tcph->window));
				printf("URG:%d ACK:%d PSH:%d RST:%d SYN:%d FIN:%d\n", 
				tcph->urg, tcph->ack, tcph->psh, tcph->rst, 
				tcph->syn, tcph->fin, ntohs(tcph->check), 
				ntohs(tcph->urg_ptr));
				printf("\n===================   TCP DATA(HEX)  =================\n"); 
				chcnt = 0;
				for(temp = (iph->ihl * 4) + (tcph->doff * 4); temp <= ntohs(iph->tot_len) - 1; temp++) {
					printf("%02x ", *(tcpdata++));
					if( (++chcnt % 16) == 0 ) printf("\n");
				}
				if (pflag) {
				   tcpdata = (unsigned char *) (p + (iph->ihl*4) + (tcph->doff * 4));
				   printf("\n===================   TCP DATA(CHAR)  =================\n"); 
				   for(temp = (iph->ihl * 4) + (tcph->doff * 4); temp <= ntohs(iph->tot_len) - 1; temp++) {
						temp_char = *tcpdata;
						if ( (temp_char == 0x0d) && ( *(tcpdata+1) == 0x0a ) ) {
							fprintf(stdout,"\n");
							tcpdata += 2;
							temp++;
							continue;
						}
						temp_char = ( ( temp_char >= ' ' ) && ( temp_char < 0x7f ) )? temp_char : '.';
						printf("%c", temp_char);
						tcpdata++;							
				   }
				}
				printf("\n>>>>> End of Data >>>>>\n");
			}
			else if(iph->protocol == IPPROTO_UDP) {
				udph = (struct udphdr *) (p + iph->ihl * 4);
				udpdata = (unsigned char *) (p + iph->ihl*4) + 8;
				printf("\n==================== UDP HEADER =====================\n");
				printf("Source Port :      %d\n",ntohs(udph->source));
				printf("Destination Port : %d\n", ntohs(udph->dest));
				printf("Length :           %d\n", ntohs(udph->len));
				printf("Checksum :         %x\n", ntohs(udph->check));
						printf("\n===================  UDP DATA(HEX)  ================\n");   
				chcnt = 0;
				for(temp = (iph->ihl*4)+8; temp<=ntohs(iph->tot_len) -1; temp++) {
				   printf("%02x ", *(udpdata++));
				   if( (++chcnt % 16) == 0) printf("\n"); 
				}

				udpdata = (unsigned char *) (p + iph->ihl*4) + 8;
				if(pflag) {
					printf("\n===================  UDP DATA(CHAR)  ================\n");     
					for(temp = (iph->ihl*4)+8; temp<=ntohs(iph->tot_len) -1; temp++)  {
						temp_char = *udpdata;
						if ( (temp_char == 0x0d) && ( *(udpdata+1) == 0x0a ) ) {
							fprintf(stdout,"\n");
							udpdata += 2;
							temp++;
							continue;
						}
						temp_char = ( ( temp_char >= ' ' ) && ( temp_char < 0x7f ) )? temp_char : '.';
						printf("%c", temp_char);
						udpdata++;							
					}
				}
				
				printf("\n>>>>> End of Data >>>>>\n");
			}         
			else if(iph->protocol == IPPROTO_ICMP) {
				icmph = (struct icmp *) (p + iph->ihl * 4);
				icmpdata = (unsigned char *) (p + iph->ihl*4) + 8;
				printf("\n\n===================   ICMP HEADER   ===================\n");
				printf("Type :                    %d\n", icmph->icmp_type);
				printf("Code :                    %d\n", icmph->icmp_code);
				printf("Checksum :                %02x\n", icmph->icmp_cksum);
				printf("ID :                      %d\n", icmph->icmp_id);
				printf("Seq :                     %d\n", icmph->icmp_seq);
				printf("\n===================   ICMP DATA(HEX)  =================\n"); 
				chcnt = 0;
				for(temp = (iph->ihl * 4) + 8; temp <= ntohs(iph->tot_len) - 1; temp++) {
					printf("%02x ", *(icmpdata++));
					if( (++chcnt % 16) == 0 ) printf("\n");
				}
				printf("\n>>>>> End of Data >>>>>\n");
		   }
		}   
	}
}

void sig_int(int sig)
{
    printf("Bye!!\n");
    pcap_close(pd);
    close(sockfd);
    exit(0);
}

void usage(void)
{
    fprintf(stdout," Usage : noh_pa filter_rule [-pch]\n");
    fprintf(stdout,"         -p  :  데이타를 문자로 출력한다.\n");
    fprintf(stdout,"         -c  :  주어진 숫자만큼의 패킷만 덤프한다\n");
    fprintf(stdout,"         -e  :  datalink layer를 출력한다.\n");
    fprintf(stdout,"         -r  :  잡은 패킷을 생으로 찍는다.\n");
    fprintf(stdout,"         -h  :  사용법\n");
}

int main(int argc, char *argv[])
{
	struct  bpf_program fcode;
	pcap_handler printer;
	char    ebuf[PCAP_ERRBUF_SIZE];
	int     c, i, snaplen = 1514, size, packetcnt;
	bpf_u_int32 myself, localnet, netmask;
	unsigned char   *pcap_userdata;
			
	filter_rule = argv[1];          /* example : "src host xxx.xxx.xxx.xxx and tcp port 80" */
	
	signal(SIGINT,sig_int);
	
	opterr = 0;
	
	if(argc-1 < 1) {
		usage(); 
		exit(1);
	}
	
	while( (c = getopt(argc, argv,"i:c:pher")) != -1) {
		switch(c) {
			case 'i'  :
				device = optarg;
				break;
			case 'p' :
				pflag = 1; 
				break;
			case 'c' :
				cflag = 1; 
				packetcnt = atoi(optarg);
				if(packetcnt <= 0) {
					fprintf(stderr,"invalid number %s",optarg);
					exit(1);
				}
				break;
			case 'e' :
				eflag = 1;
				break;          
			case 'r' :
				rflag = 1;
				break;          
			case 'h' :
				usage();
				exit(1);
		}
	}           
	
	if (device == NULL ) {
		if ( (device = pcap_lookupdev(ebuf) ) == NULL) {
			perror(ebuf);           
			exit(-1);
		}
	}
	fprintf(stdout, "device = %s\n", device);
	
	pd = pcap_open_live(device, snaplen, PROMISCUOUS, 1000, ebuf);
	if(pd == NULL) {
		perror(ebuf);          
		exit(-1);
	}
	
	i = pcap_snapshot(pd);
	if(snaplen < i) {
		perror(ebuf);                            
		exit(-1);
	}
	
	if(pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
		perror(ebuf);
		exit(-1);
	}
	
	setuid(getuid());
	
	if(pcap_compile(pd, &fcode, filter_rule, 0, netmask) < 0) {
		perror(ebuf);
		exit(-1);
	}
	
	if(pcap_setfilter(pd, &fcode) < 0) {
		perror(ebuf);
		exit(-1);
	}
	
	fflush(stderr);
	
	printer = lookup_printer(pcap_datalink(pd));
	pcap_userdata = 0;
	
	if(pcap_loop(pd, packetcnt, printer, pcap_userdata) < 0) {
		perror("pcap_loop error");
		exit(-1);
	}
	
	pcap_close(pd);
	exit(0);
}
	
