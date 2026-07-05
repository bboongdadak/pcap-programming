#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <pcap.h>
#include <arpa/inet.h>

#include "myheader.h"

#define ETHER_TYPE_IP 0x0800
#define MAX_PAYLOAD_PRINT 512

void print_mac(const u_char *mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_payload(const u_char *payload, int payload_len)
{
    if (payload_len <= 0) {
        printf("(No TCP payload)\n");
        return;
    }

    int print_len = payload_len;

    if (print_len > MAX_PAYLOAD_PRINT) {
        print_len = MAX_PAYLOAD_PRINT;
    }

    for (int i = 0; i < print_len; i++) {
        unsigned char c = payload[i];

        if (isprint(c) || c == '\n' || c == '\r' || c == '\t') {
            putchar(c);
        } else {
            putchar('.');
        }
    }

    if (payload_len > MAX_PAYLOAD_PRINT) {
        printf("\n... (%d bytes omitted)", payload_len - MAX_PAYLOAD_PRINT);
    }

    printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    (void)args;

    if (header->caplen < sizeof(struct ethheader)) {
        return;
    }

    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) != ETHER_TYPE_IP) {
        return;
    }

    if (header->caplen < sizeof(struct ethheader) + sizeof(struct ipheader)) {
        return;
    }

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    if (ip->iph_protocol != IPPROTO_TCP) {
        return;
    }

    int ip_header_len = ip->iph_ihl * 4;

    if (ip_header_len < 20) {
        return;
    }

    if (header->caplen < sizeof(struct ethheader) + ip_header_len + sizeof(struct tcpheader)) {
        return;
    }

    struct tcpheader *tcp = (struct tcpheader *)
        (packet + sizeof(struct ethheader) + ip_header_len);

    int tcp_header_len = TH_OFF(tcp) * 4;

    if (tcp_header_len < 20) {
        return;
    }

    int total_header_len = sizeof(struct ethheader)
                         + ip_header_len
                         + tcp_header_len;

    if ((int)header->caplen < total_header_len) {
        return;
    }

    int ip_total_len = ntohs(ip->iph_len);

    int payload_len = ip_total_len
                    - ip_header_len
                    - tcp_header_len;

    if (payload_len < 0) {
        payload_len = 0;
    }

    int captured_payload_len = header->caplen - total_header_len;

    if (payload_len > captured_payload_len) {
        payload_len = captured_payload_len;
    }

    const u_char *payload = packet + total_header_len;

    printf("\n================ Packet ================\n");

    printf("[Ethernet Header]\n");
    printf("Src MAC: ");
    print_mac(eth->ether_shost);
    printf("\n");

    printf("Dst MAC: ");
    print_mac(eth->ether_dhost);
    printf("\n");

    printf("\n[IP Header]\n");
    printf("Src IP : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Dst IP : %s\n", inet_ntoa(ip->iph_destip));

    printf("\n[TCP Header]\n");
    printf("Src Port: %d\n", ntohs(tcp->tcp_sport));
    printf("Dst Port: %d\n", ntohs(tcp->tcp_dport));

    printf("\n[TCP Payload / HTTP Message]\n");
    print_payload(payload, payload_len);

    printf("========================================\n");
}

int main(int argc, char *argv[])
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    char filter_exp[] = "tcp";

    if (argc != 2) {
        printf("Usage: sudo %s <interface>\n", argv[0]);
        printf("Example: sudo %s eth0\n", argv[0]);
        printf("Example: sudo %s enp0s3\n", argv[0]);
        printf("Example: sudo %s lo\n", argv[0]);
        return 1;
    }

    char *dev = argv[1];

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
        return 1;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not compile filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error");
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }

    printf("Sniffing on interface: %s\n", dev);
    printf("Filter: %s\n", filter_exp);
    printf("Press Ctrl+C to stop.\n");

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}
