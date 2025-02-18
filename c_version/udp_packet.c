#include "udp_packet.h"
#include <stdio.h>
#include <arpa/inet.h>

void udp_parse(Packet *self, const u_char *data, uint32_t len) 
{
    if(len < 8) 
    {
        fprintf(stderr, "UDP Packet too short (len=%u)\n", len);
        return;
    }

    UDPPacket *udp = (UDPPacket *)self;
    udp->src_port = ntohs(*(uint16_t *)(data));
    udp->dst_port = ntohs(*(uint16_t *)(data+2));
    udp->len = ntohs(*(uint16_t *)(data+4));
    udp->checksum = ntohs(*(uint16_t *)(data+6));

    printf("[UDP] Src Port: %d, Dst Port: %d, Length: %d\n", udp->src_port, udp->dst_port, udp->len);
}
