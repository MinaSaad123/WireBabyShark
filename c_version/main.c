#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// Callback function called by pcap for each captured packet
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct iphdr *ip = (struct iphdr*)(packet + 14); // Skip Ethernet header (14 bytes)
    
    printf("Packet captured:\n");
    printf("IP Header:\n");
    printf("   |-IP Version        : %d\n", (unsigned int)ip->version);
    printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)ip->ihl, ((unsigned int)(ip->ihl)) * 4);
    printf("   |-Type Of Service   : %d\n", (unsigned int)ip->tos);
    printf("   |-IP Total Length   : %d Bytes(Size of Packet)\n", ntohs(ip->tot_len));
    printf("   |-Identification    : %d\n", ntohs(ip->id));
    printf("   |-TTL      : %d\n", (unsigned int)ip->ttl);
    printf("   |-Protocol : %d\n", (unsigned int)ip->protocol);
    printf("   |-Checksum : %d\n", ntohs(ip->check));
    printf("   |-Source IP        : %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
    printf("   |-Destination IP   : %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr*)(packet + 14 + ip->ihl * 4);
        printf("TCP Header:\n");
        printf("   |-Source Port      : %u\n", ntohs(tcp->source));
        printf("   |-Destination Port : %u\n", ntohs(tcp->dest));
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr*)(packet + 14 + ip->ihl * 4);
        printf("UDP Header:\n");
        printf("   |-Source Port      : %u\n", ntohs(udp->source));
        printf("   |-Destination Port : %u\n", ntohs(udp->dest));
    }
    
    printf("\n");
}

int main() {
    char *dev = "enp0s3"; // Change this to your network interface
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    // Open the device for packet capture
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }
    
    // Capture packets indefinitely
    pcap_loop(handle, 0, packet_handler, NULL);
    
    // Close the handle
    pcap_close(handle);
    
    return 0;
}