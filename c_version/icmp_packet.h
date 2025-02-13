#ifndef ICMP_PACKET_H
#define ICMP_PACKET_H

#include "packet.h"

// ICMPPacket "inherits" from Packet.
typedef struct ICMPPacket {
    Packet base;
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
} ICMPPacket;

// Parse function for ICMP packets.
void icmp_parse(Packet *self, const u_char *data, uint32_t len);

#endif /* ICMP_PACKET_H */
