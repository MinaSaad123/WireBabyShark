#ifndef UDP_PACKET_H
#define UDP_PACKET_H

#include "packet.h"

// UDPPacket "inherits" from Packet.
typedef struct UDPPacket 
{
    Packet base;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
    
} UDPPacket;

// Parse function for UDP packets.
void udp_parse(Packet *self, const u_char *data, uint32_t len);

#endif /* UDP_PACKET_H */
