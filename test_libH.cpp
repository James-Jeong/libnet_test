#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <libnet.h>
#include "libnet-headers.h"
#include "libnet-functions.h"
#include "libnet-macros.h"
#include "libnet-structures.h"
#include "libnet-types.h"

// sudo apt install libnet-dev

char WIP[2]; // what_is_protocol
uint8_t Print_Eth(const u_char* Packet_DATA){
    struct libnet_ethernet_hdr* EH = (struct libnet_ethernet_hdr*)(Packet_DATA);
    uint8_t EH_length = (uint8_t)(sizeof(EH));
    u_short ethernet_type;
    ethernet_type = ntohs(EH->ether_type);

    if(ethernet_type != 0x0800){
        printf("Ethernet type is not IP\n");
        return 0;
    } // IP CHECK

    printf("[Source] <MAC> Address : %02x:%02x:%02x:%02x:%02x:%02x:\n",
           EH->ether_shost[0],
            EH->ether_shost[1],
             EH->ether_shost[2],
              EH->ether_shost[3],
               EH->ether_shost[4],
                EH->ether_shost[5]);

    printf("[Destination] <MAC> Address : %02x:%02x:%02x:%02x:%02x:%02x:\n",
           EH->ether_dhost[0],
            EH->ether_dhost[1],
             EH->ether_dhost[2],
              EH->ether_dhost[3],
               EH->ether_dhost[4],
                EH->ether_dhost[5]);
    return EH_length;
}

char* Print_IP(const u_char* Packet_DATA){
    struct libnet_ipv4_hdr* IH = (struct libnet_ipv4_hdr*)(Packet_DATA);

    // IP Check
    if(IH->ip_hl == 0) return 0;
    if(IH->ip_v < 4 && IH->ip_v > 9) return 0;
    // 4 : IP
    // 5 : ST
    // 6 : SIP, SIPP, IPv6
    // 7 : TP/IX
    // 8 : PIP
    // 9 : TUBA

    printf("Type of service : %x\n", IH->ip_tos);
    printf("Total length : %x\n", IH->ip_len);
    printf("Identification : %x\n", IH->ip_id);
    printf("TTL : %x\n", IH->ip_ttl);
    printf("protocol : %x\n", IH->ip_p);
    printf("Checksum : %x\n", IH->ip_sum);

    sprintf(WIP, "%x", IH->ip_p);
    //printf("WIP : %s\n", WIP);

    printf("[Source] <IP> Address : %s\n", inet_ntoa(IH->ip_src));
    printf("[Destination] <IP> Address : %s\n", inet_ntoa(IH->ip_dst));

    return WIP;
}

int print_TCP(const u_char* Packet_DATA){
    struct libnet_tcp_hdr* TH = (struct libnet_tcp_hdr*)(Packet_DATA);

    // TCP data offset check
    if(TH->th_off < 4) return 0;

    char* sp = (char*)malloc(sizeof(TH->th_sport));
    sprintf(sp, "%d", ntohs(TH->th_sport));
    char* dp = (char*)malloc(sizeof(TH->th_dport));
    sprintf(dp, "%d", ntohs(TH->th_dport));

    //printf("sp : %s\n", sp);
    //printf("dp : %s\n", dp);

    if((!strcmp(sp, "443")) || (!strcmp(dp, "443"))){
        printf("TCP SSL(HTTPS) protocol\n");
    }
    else if((!strcmp(sp, "25")) || (!strcmp(dp, "25"))){
        printf("TCP SMTP protocol\n");
    }
    else if((!strcmp(sp, "53")) || (!strcmp(dp, "53"))){
        printf("TCP DNS protocol\n");
    }
    else if((!strcmp(sp, "80")) || (!strcmp(dp, "80"))){
        printf("TCP HTTP protocol\n");
    }
    else if((!strcmp(sp, "22")) || (!strcmp(dp, "22"))){
        printf("TCP SSH protocol\n");
    }
    else if((!strcmp(sp, "23")) || (!strcmp(dp, "23"))){
        printf("TCP Telnet protocol\n");
    }
    else if((!strcmp(sp, "111")) || (!strcmp(dp, "111"))){
        printf("TCP RPC protocol\n");
    }

    printf("[Source] <Port> Number : %d\n", ntohs(TH->th_sport));
    printf("[Destination] <Port> Number : %d\n", ntohs(TH->th_dport));

    return ((TH->th_off) * 4);
}


int print_UDP(const u_char* Packet_DATA){
    struct libnet_udp_hdr* UH = (struct libnet_udp_hdr*)(Packet_DATA);

    char* sp = (char*)malloc(sizeof(UH->uh_sport));
    sprintf(sp, "%d", ntohs(UH->uh_sport));
    char* dp = (char*)malloc(sizeof(UH->uh_dport));
    sprintf(dp, "%d", ntohs(UH->uh_dport));

    //printf("sp : %s\n", sp);
    //printf("dp : %s\n", dp);

    if((!strcmp(sp, "80")) || (!strcmp(dp, "80"))){
        printf("UDP HTTP protocol\n");
    }
    else if((!strcmp(sp, "161")) || (!strcmp(dp, "161"))){
        printf("UDP SNMP protocol\n");
    }
    else if((!strcmp(sp, "111")) || (!strcmp(dp, "111"))){
        printf("UDP RPC protocol\n");
    }

    printf("[Source] <Port> Number : %d\n", ntohs(UH->uh_sport));
    printf("[Destination] <Port> Number : %d\n", ntohs(UH->uh_dport));

    printf("UDP Length : %x\n", UH->uh_ulen);
    printf("UDP checksum : %x\n", UH->uh_sum);

    return (UH->uh_ulen);
}

void print_Data(const u_char* Packet_DATA){
    for(int i = 0; i < 10; i++) printf("%02x ", Packet_DATA[i]);
    printf("\n");
}


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
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    printf("########################\n\n");
    printf("-- %u Bytes captured --\n\n", header->caplen);

    printf("-------_Ethernet_-------\n");
    uint8_t tmp = 0; // Ethernet header size
    tmp = Print_Eth(packet);
    //printf("packet : %d\n", tmp);
    if(tmp > 14) break;
    printf("\n");

    printf("----------_IP_----------\n");
    packet += 14;
    char* tmp2; // IP protocol type
    int WIP = 0; // protocol's header size
    tmp2 = Print_IP(packet);
    printf("\n");

    //printf("tmp2 = %s\n", tmp2);
    if(!strcmp(tmp2, "6")){ // TCP header : 20 Bytes
        WIP = 20;
    }
    else if(!strcmp(tmp2, "11") || !strcmp(tmp2, "1")){
        WIP = 8; // UDP header & ICMP header : 8 Bytes
    }
    else if(!strcmp(tmp2, "84")){
        WIP = 4; // SCTP header : 4Bytes
    }

    if(!strcmp(tmp2, "6"))
        printf("---------_TCP_---------\n");
    else if(!strcmp(tmp2, "11"))
        printf("---------_UDP_---------\n");
    else
        printf("--------_Protocol_--------\n");

    packet += 20;
    if(!strcmp(tmp2, "6"))
        print_TCP(packet);
    else if(!strcmp(tmp2, "11"))
        print_UDP(packet);
    else
        printf("No Header Data here for this protocol!\n");
    //printf("WIP : %d\n", WIP);
    printf("\n");

    printf("---------_DATA_---------\n");
    packet += WIP;
    if((!strcmp(tmp2, "6")) || (!strcmp(tmp2, "11")))
        print_Data(packet);
    else
        printf("No Protocol Data here!\n");
    printf("\n");

    printf("########################\n");
    printf("\n\n");
  }

  pcap_close(handle);
  return 0;
} 
