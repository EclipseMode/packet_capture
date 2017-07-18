#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <pcap.h>
#include <arpa/inet.h>

void Check_Packet(u_char*, const struct pcap_pkthdr*, const u_char*);
void Ip_Packet_Printer(const u_char*, int);
void Tcp_Packet_Printer(const u_char*, int);
void Eth_Packet_Printer(const u_char*, int);
void Payload_Printer(const u_char*, int);

struct sockaddr_in source, destination; // address and port of socket
int i,j; // index var

int main(void){
    pcap_if_t* device; // Find a device.
    pcap_t *handle; // handler
    
    char errbuf[PCAP_ERRBUF_SIZE];
    char *devname = pcap_lookupdev(errbuf); // get device name
    printf("Device : %s\n", devname); 
    handle = pcap_open_live(devname,65536,1,0,errbuf); // make packet capture descriptor
    pcap_loop(handle, -1, Check_Packet, NULL);
    return 0;
}

void Check_Packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buf){
	int size = header->len;
	struct iphdr *iph = (struct iphdr*)(buf + sizeof(struct ethhdr));
    if(iph->protocol == 6) Tcp_Packet_Printer(buf,size);
    else printf("Not a TCP Packet\n\n\n\n\n\n");
}

void Eth_Packet_Printer(const u_char* buf, int size){
    struct ethhdr *eth = (struct ethhdr* )buf;
    printf("        SOURCE MAC : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("        DEST   MAC : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
}

void Ip_Packet_Printer(const u_char* buf, int size){
    Eth_Packet_Printer(buf,size);
	unsigned short IP_HEADER_LENGTH;
	struct iphdr* iph = (struct iphdr* )(buf + sizeof(struct ethhdr));
	IP_HEADER_LENGTH = iph->ihl * 4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph -> saddr;
    memset(&destination, 0, sizeof(destination));
    destination.sin_addr.s_addr = iph->daddr;
    
    printf("        SOURCE IP  : %s\n", inet_ntoa(source.sin_addr));
    printf("        DEST   IP  : %s\n", inet_ntoa(destination.sin_addr));   
}


void Tcp_Packet_Printer(const u_char* buf, int size){
    unsigned short IP_HEADER_LENGTH;
    struct iphdr* iph = (struct iphdr* )(buf + sizeof(struct ethhdr));
    IP_HEADER_LENGTH = iph -> ihl * 4;
    struct tcphdr* tcph = (struct tcphdr* )(buf + IP_HEADER_LENGTH + sizeof(struct ethhdr));
    int header_size = sizeof(struct ethhdr) + IP_HEADER_LENGTH + tcph->doff * 4;

    Ip_Packet_Printer(buf,size);
    printf("        SOURCE PT : %u\n", ntohs(tcph -> source));
    printf("        DEST   PT : %u\n", ntohs(tcph -> dest));

    Payload_Printer(buf + header_size, size - header_size);
}     

void Payload_Printer(const u_char* data, int size){
    int i, j;
    for(i = 0 ; i < size ; i++){
        if(i != 0 && i % 16 == 0){
            printf("        ");
            for(j = i-16; j < i ; j++){
                if(data[j] >= 32 && data[j] <= 128) printf("%c",(unsigned char) data[j]); // alphabet or num
                else printf(".");           
              }
            printf("\n");
         }
        if(i%16 == 0) printf("       ");
            printf(" %02X", (unsigned int)data[i]);
        if(i == size -1){
            for(j = 0 ; j < 15 - i % 16 ; j++){
                printf("   ");
              }
            printf("         ");
            for(j = i - i%16; j <= i ; j++){
                if(data[j] >= 32 && data[j] <= 128) printf("%c",(unsigned char)data[j]);
                else printf(".");
              }
         }
     }
    printf("\n\n\n\n\n\n");
}

