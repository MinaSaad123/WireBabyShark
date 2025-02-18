#ifndef APP_PROTOCOL_H
#define APP_PROTOCOL_H

#include "packet.h"

// Application Protocol "class" (base for HTTP, DNS, FTP, etc.)
typedef struct AppProtocol 
{
    Packet base;
    // Common application-layer fields could be added here.
} AppProtocol;

// Stub functions for application protocols.
void http_parse(Packet *self, const u_char *data, uint32_t len);
void dns_parse(Packet *self, const u_char *data, uint32_t len);
void ftp_parse(Packet *self, const u_char *data, uint32_t len);

#endif /* APP_PROTOCOL_H */
