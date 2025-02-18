#ifndef TCP_PACKET_H
#define TCP_PACKET_H

#include "packet.h"

// TCPPacket "inherits" from Packet.
typedef struct TCPPacket 
{
    Packet base; // Base Packet
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t data_offset; // In 32-bit words
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
    
} TCPPacket;

// Parse function for TCP packets.
void tcp_parse(Packet *self, const u_char *data, uint32_t len);

#endif /* TCP_PACKET_H */
