// sudo apt install libnet-dev

#include "stdafx.h"
#include "mod_Eth.h"
#include "mod_IP.h"
#include "mod_TCP.h"
#include "mod_UDP.h"

void Print_Data(const u_char* Packet_DATA){
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
    Ethernet_header Eh;
    tmp = Eh.Print_Eth(packet);
    //printf("packet : %d\n", tmp);
    if(tmp > 14) break;
    printf("\n");

    printf("----------_IP_----------\n");
    packet += 14;
    char* tmp2; // IP protocol type
    int WIP = 0; // protocol's header size
    IP_header Ih;
    tmp2 = Ih.Print_IP(packet);
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
    if(!strcmp(tmp2, "6")){
        TCP_header Th;
        Th.Print_TCP(packet);
    }
    else if(!strcmp(tmp2, "11")){
        UDP_header Uh;
        Uh.Print_UDP(packet);
    }
    else
        printf("No Header Data here for this protocol!\n");
    //printf("WIP : %d\n", WIP);
    printf("\n");

    printf("---------_DATA_---------\n");
    packet += WIP;
    if((!strcmp(tmp2, "6")) || (!strcmp(tmp2, "11")))
        Print_Data(packet);
    else
        printf("No Protocol Data here!\n");
    printf("\n");

    printf("########################\n");
    printf("\n\n");
  }

  pcap_close(handle);
  return 0;
} 
