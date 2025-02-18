#include "icmp_packet.h"
#include <stdio.h>
#include <arpa/inet.h>

void icmp_parse(Packet *self, const u_char *data, uint32_t len) 
{
    if(len < 4) 
    {
        fprintf(stderr, "ICMP Packet too short (len=%u)\n", len);
        return;
    }
    
    ICMPPacket *icmp = (ICMPPacket *)self;
    icmp->type = data[0];
    icmp->code = data[1];
    icmp->checksum = ntohs(*(uint16_t *)(data+2));

    printf("[ICMP] Type: %d, Code: %d\n", icmp->type, icmp->code);
}
