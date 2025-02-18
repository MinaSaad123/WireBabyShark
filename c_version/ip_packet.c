#include "ip_packet.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

void ip_parse(Packet *self, const u_char *data, uint32_t len) 
{
    if(len < 20) 
    {
        fprintf(stderr, "IP Packet too short (len=%u)\n", len);
        return;
    }

    IPPacket *ip = (IPPacket *)self;

    ip->version = data[0] >> 4;
    ip->ihl = data[0] & 0x0F;

    if(ip->ihl < 5) 
    {
        fprintf(stderr, "Invalid IP header length: %d\n", ip->ihl);
        return;
    }

    ip->tos = data[1];
    ip->tot_len = ntohs(*(uint16_t *)(data+2));
    ip->id = ntohs(*(uint16_t *)(data+4));
    ip->frag_off = ntohs(*(uint16_t *)(data+6));
    ip->ttl = data[8];
    ip->protocol = data[9];
    ip->check = ntohs(*(uint16_t *)(data+10));
    memcpy(&ip->src, data+12, 4);
    memcpy(&ip->dst, data+16, 4);

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->src), src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->dst), dst, INET_ADDRSTRLEN);
    ip->frag_off = ntohs(*(uint16_t *)(data+6));

    printf("[IP] %s -> %s, Protocol: %d, Total Length: %d\n", src, dst, ip->protocol, ip->tot_len);
}
