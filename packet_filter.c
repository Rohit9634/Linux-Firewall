#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Assuming Ethernet header
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header->ip_hl * 4); // Assuming IP header

    // Define your filtering rules here
    char *src_ip = "142.250.194.238"; // Example source IP to allow
    int src_port = 443; // Example source port to allow

    // Check the source IP and port against your rules
    if (strcmp(inet_ntoa(ip_header->ip_src), src_ip) == 0 && ntohs(tcp_header->th_sport) == src_port) {
        printf("Packet allowed: %s:%d -> %s:%d\n", inet_ntoa(ip_header->ip_src), ntohs(tcp_header->th_sport), inet_ntoa(ip_header->ip_dst), ntohs(tcp_header->th_dport));
    } else {
        printf("Packet blocked: %s:%d -> %s:%d\n", inet_ntoa(ip_header->ip_src), ntohs(tcp_header->th_sport), inet_ntoa(ip_header->ip_dst), ntohs(tcp_header->th_dport));
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the network interface for capturing
    handle = pcap_open_live("enp24s0", BUFSIZ, 1, 1000, errbuf); // Change "eth0" to your network interface name

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }

    // Set a BPF filter to capture only TCP packets
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // Start packet capturing
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the capture handle when done
    pcap_close(handle);

    return 0;
}
