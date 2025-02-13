#include "app_protocol.h"
#include <stdio.h>
#include <string.h>

void http_parse(Packet *self, const u_char *data, uint32_t len) {
    // Basic detection based on common HTTP methods.
    if(len < 4) return;
    if (strncmp((const char *)data, "GET ", 4) == 0 ||
        strncmp((const char *)data, "POST", 4) == 0 ||
        strncmp((const char *)data, "HTTP", 4) == 0) {
        printf("[HTTP] HTTP packet detected\n");
    }
}

void dns_parse(Packet *self, const u_char *data, uint32_t len) {
    // DNS packet stub
    printf("[DNS] DNS packet detected (stub)\n");
}

void ftp_parse(Packet *self, const u_char *data, uint32_t len) {
    // FTP packet stub
    printf("[FTP] FTP packet detected (stub)\n");
}
