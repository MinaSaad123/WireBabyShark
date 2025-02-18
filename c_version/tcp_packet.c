#include "tcp_packet.h"
#include <stdio.h>
#include <arpa/inet.h>

void tcp_parse(Packet *self, const u_char *data, uint32_t len) 
{
    if(len < 20) 
    {
        fprintf(stderr, "TCP Packet too short (len=%u)\n", len);
        return;
    }

    TCPPacket *tcp = (TCPPacket *)self;
    tcp->src_port = ntohs(*(uint16_t *)(data));
    tcp->dst_port = ntohs(*(uint16_t *)(data+2));
    tcp->seq = ntohl(*(uint32_t *)(data+4));
    tcp->ack = ntohl(*(uint32_t *)(data+8));
    tcp->data_offset = data[12] >> 4;
    tcp->flags = data[13];
    tcp->window = ntohs(*(uint16_t *)(data+14));
    tcp->checksum = ntohs(*(uint16_t *)(data+16));
    tcp->urgent_ptr = ntohs(*(uint16_t *)(data+18));

    printf("[TCP] Src Port: %d, Dst Port: %d, Seq: %u, Ack: %u\n", tcp->src_port, tcp->dst_port, tcp->seq, tcp->ack);
}
