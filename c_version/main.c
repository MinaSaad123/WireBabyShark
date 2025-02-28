#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>    // For getopt
#include <arpa/inet.h>
#include "ip_packet.h"
#include "tcp_packet.h"
#include "udp_packet.h"
#include "icmp_packet.h"
#include "app_protocol.h"

#define ETHERNET_HEADER_SIZE 14

// Global dumper for writing packets to file.
pcap_dumper_t *dumper = NULL;

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) 
{
    // Dump the raw packet to the file.
    if(dumper)
    {
        pcap_dump(user, header, packet);
    }
    
    const u_char *ip_packet_data = packet + ETHERNET_HEADER_SIZE;

    uint32_t ip_packet_len = header->caplen - ETHERNET_HEADER_SIZE;

    // Create and parse an IPPacket.
    IPPacket ip;
    ip.base.parse = ip_parse;
    ip.base.parse( (Packet *)&ip, ip_packet_data, ip_packet_len );

    uint32_t ip_header_len = ip.ihl * 4;

    if(ip_packet_len < ip_header_len) 
        return;

    // Decide which protocol to parse based on IP header.
    switch(ip.protocol) 
    {
        case 6: // TCP
        { 
            const u_char *tcp_data = ip_packet_data + ip_header_len;
            uint32_t tcp_len = ip_packet_len - ip_header_len;
            TCPPacket tcp;

            tcp.base.parse = tcp_parse;
            tcp.base.parse((Packet *)&tcp, tcp_data, tcp_len);

            // Example: Check for HTTP (port 80/8080) or FTP (port 21).
            if(tcp.src_port == 80 || tcp.dst_port == 80 ||
               tcp.src_port == 8080 || tcp.dst_port == 8080) 
            {
                uint32_t tcp_header_len = tcp.data_offset * 4;

                if(tcp_len > tcp_header_len)
                    http_parse((Packet *)&tcp, tcp_data + tcp_header_len, tcp_len - tcp_header_len);
            }

            else if(tcp.src_port == 21 || tcp.dst_port == 21) 
            {
                uint32_t tcp_header_len = tcp.data_offset * 4;
                if(tcp_len > tcp_header_len)
                    ftp_parse((Packet *)&tcp, tcp_data + tcp_header_len, tcp_len - tcp_header_len);
            }

            break;
        }

        case 17: // UDP
        { 
            const u_char *udp_data = ip_packet_data + ip_header_len;
            uint32_t udp_len = ip_packet_len - ip_header_len;
            UDPPacket udp;

            udp.base.parse = udp_parse;
            udp.base.parse((Packet *)&udp, udp_data, udp_len);

            // Example: Check for DNS (port 53).
            if(udp.src_port == 53 || udp.dst_port == 53) 
            {
                if(udp_len > 8)
                    dns_parse((Packet *)&udp, udp_data + 8, udp_len - 8);
            }
            break;
        }
        case 1: // ICMP
        { 
            const u_char *icmp_data = ip_packet_data + ip_header_len;
            uint32_t icmp_len = ip_packet_len - ip_header_len;
            ICMPPacket icmp;

            icmp.base.parse = icmp_parse;
            icmp.base.parse((Packet *)&icmp, icmp_data, icmp_len);
            break;
        }

        default:
            printf("[Info] Other IP Protocol: %d\n", ip.protocol);
            break;
    }
}

void usage(const char *progname) 
{
    fprintf(stderr, "Usage: %s -i <interface> [-f <filter expression>]\n", progname);
}

void die1(const char* message, const char *arg1, const char* arg2) 
{
    fprintf(stderr, message, arg1, arg2);
    exit(EXIT_FAILURE);
}

void die2(const char* message, const char *arg1) 
{
    fprintf(stderr, message, arg1);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) 
{
    char *dev = NULL;
    char *filter_exp = NULL;
    int opt;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    while ( ( opt = getopt(argc, argv, "i:f:") ) != -1) // Parse command-line options.
    {
        switch(opt) 
        {
            case 'i':
                dev = optarg;
                break;

            case 'f':
                filter_exp = optarg;
                break;
                
            default:
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if(dev == NULL) 
    {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    // Open the device for live capture.
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) 
    {
        die1("Couldn't open device %s: %s\n", dev, errbuf);
    }

    if (strlen(filter_exp) > 0)     // Compile and set the filter if provided.
    {
        struct bpf_program fp;

        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) 
        {
            die1("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        }

        if (pcap_setfilter(handle, &fp) == -1) 
        {
            die1("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        }

        pcap_freecode(&fp);
    }    

    if ( (dumper = pcap_dump_open(handle, "capture.pcap") ) == NULL)  // Open the dump file for saving captured packets.
    {
        die2("Couldn't open dump file: %s\n", pcap_geterr(handle));
    }

    printf("WireFish running on %s with filter '%s'.\n", dev, filter_exp);
    printf("Press Ctrl+C to stop.\n");

    // Start the capture loop.
    if (pcap_loop(handle, 0, packet_handler, (u_char *)dumper) < 0) 
    {
        die2("Error during packet capture: %s\n", pcap_geterr(handle));
    }

    // Clean up.
    pcap_dump_close(dumper);
    pcap_close(handle);

    return 0;
}