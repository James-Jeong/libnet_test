#include "stdafx.h"
#include "mod_IP.h"

char* IP_header::Print_IP(const u_char* Packet_DATA){
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
