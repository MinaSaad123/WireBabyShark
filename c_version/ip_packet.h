#ifndef IP_PACKET_H
#define IP_PACKET_H

#include "packet.h"

// IPPacket "inherits" from Packet.
typedef struct IPPacket 
{
    Packet base; // Base Packet
    uint8_t ihl:4;
    uint8_t version:4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t src;
    uint32_t dst;
    
} IPPacket;

// Parse function for IP packets.
void ip_parse(Packet *self, const u_char *data, uint32_t len);

#endif /* IP_PACKET_H */
