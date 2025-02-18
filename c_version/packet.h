#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <sys/time.h>

#define u_char unsigned char

typedef struct Packet 
{
    struct timeval ts;  // Timestamp of capture
    uint32_t caplen;    // Captured length
    uint32_t len;       // Original packet length
    void (*parse)(struct Packet *self, const u_char *data, uint32_t len); // Base Packet "class" with a polymorphic parse function.

} Packet;

#endif /* PACKET_H */
                                 