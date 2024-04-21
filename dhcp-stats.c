/** @file dhcp-stats.c
 *  @brief DHCP statistics analyzer.
 *
 *  @author Zdebska Kateryna (xzdebs00)
 *  @copyright GNU GENERAL PUBLIC LICENSE v3.0
 */

/* Includes */
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <ncurses.h>
#include <getopt.h>
#include <stdbool.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <signal.h>

#define DHCP_OPTION_MSG_TYPE 53
#define DHCPACK 5

// Global variable to indicate if a signal has been received
volatile sig_atomic_t termination_requested = 0;

// Structure to store information about IP prefixes
typedef struct {
    char *prefix;
    int max_hosts;
    int prefix_length;
    int allocated_addresses;
    float utilization;
    bool is_logged;
} PrefixInfo;

// Structure to keep track of unique allocated IPs
typedef struct {
    struct in_addr ip;
} UniqueAllocatedIP;

// Structure representing the DHCP packet
struct dhcp_packet {
    u_int8_t op;
    u_int8_t htype;
    u_int8_t hlen;
    u_int8_t hops;
    u_int32_t xid;
    u_int16_t secs;
    u_int16_t flags;
    struct in_addr ciaddr;
    struct in_addr yiaddr;
    struct in_addr siaddr;
    struct in_addr giaddr;
    u_int8_t chaddr[16];
    u_int8_t options[312];
};

/**
 * @brief Signal handler for handling Ctrl+C and termination signals.
 *
 * @param signo Signal received.
 */
void handle_signal(int signo) {
    termination_requested = 1;
    endwin(); // End ncurses
    exit(0);
}

/**
 * @brief Add an IP prefix to the array of prefixes.
 *
 * @param prefixes Pointer to the array of prefixes.
 * @param prefix_count Pointer to the count of prefixes.
 * @param prefix String representing the IP prefix.
 */
void add_prefix(PrefixInfo **prefixes, int *prefix_count, const char *prefix) {
    // Allocate memory for a new prefix 
    *prefixes = (PrefixInfo *)realloc(*prefixes, (*prefix_count + 1) * sizeof(PrefixInfo));
    if (!*prefixes) {
        fprintf(stderr, "Error allocating memory for prefixes.\n");
        exit(1);
    }

    // Parse the prefix string and initialize the corresponding fields
    (*prefixes)[*prefix_count].prefix = strdup(prefix);
    char *slash = strchr((*prefixes)[*prefix_count].prefix, '/');
    int prefix_length;
    if (slash != NULL) {
        prefix_length = atoi(slash + 1);
    } else {
        prefix_length = 32;
    }
    (*prefixes)[*prefix_count].prefix_length = prefix_length;
    (*prefixes)[*prefix_count].max_hosts = (1 << (32 - prefix_length)) - 2;
    (*prefixes)[*prefix_count].allocated_addresses = 0;
    (*prefixes)[*prefix_count].utilization = 0.0;
    (*prefixes)[*prefix_count].is_logged = false;
    (*prefix_count)++;
}

/**
 * @brief Process a DHCP packet and update statistics.
 *
 * @param prefixes Pointer to the array of prefixes.
 * @param prefix_count Pointer to the count of prefixes.
 * @param unique_ips Pointer to the array of unique allocated IPs.
 * @param unique_ip_count Pointer to the count of unique allocated IPs.
 * @param packet Pointer to the packet data.
 * @param length Length of the packet.
 * @param interface Interface name.
 */
void processPacket(PrefixInfo **prefixes, int *prefix_count, UniqueAllocatedIP **unique_ips, int *unique_ip_count, const u_char *packet, int length, char *interface) {
    // Extract DHCP packet from the raw packet data
    struct dhcp_packet *dhcp_pkt = (struct dhcp_packet *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
    struct in_addr allocated_ip;
    allocated_ip = dhcp_pkt->yiaddr;

    // Check if the allocated IP is already counted
    bool already_counted = false;
    for (int j = 0; j < *unique_ip_count; j++) {
        if ((*unique_ips)[j].ip.s_addr == allocated_ip.s_addr) {
            already_counted = true;
            break;
        }
    }

    // Check if the allocated IP address falls within any of the specified prefixes
    if (!already_counted) {
        for (int i = 0; i < *prefix_count; i++) {
            struct in_addr prefix_network;
            // Extract network part from the prefix string
            char network_str[INET_ADDRSTRLEN] = {};
            strncpy(network_str, (*prefixes)[i].prefix, strchr((*prefixes)[i].prefix, '/') - (*prefixes)[i].prefix);
            network_str[strchr((*prefixes)[i].prefix, '/') - (*prefixes)[i].prefix] = '\0';
            inet_pton(AF_INET, network_str, &prefix_network);

            // Apply the network mask to the allocated IP
            struct in_addr masked_allocated_ip;
            masked_allocated_ip.s_addr = allocated_ip.s_addr & htonl(0xFFFFFFFF << (32 - (*prefixes)[i].prefix_length));

            // If the masked allocated IP matches the network address
            if (memcmp(&masked_allocated_ip, &prefix_network, sizeof(struct in_addr)) == 0) {
                struct in_addr broadcast_address;
                // Calculate the broadcast address using memcpy
                memcpy(&broadcast_address, &prefix_network, sizeof(struct in_addr));
                uint32_t inverted_mask = htonl(0xFFFFFFFF << (32 - (*prefixes)[i].prefix_length));
                broadcast_address.s_addr |= ~inverted_mask;

                // Check if the allocated IP is within the valid range
                if (!(memcmp(&allocated_ip, &prefix_network, sizeof(struct in_addr)) == 0) &&
                    !(memcmp(&allocated_ip, &broadcast_address, sizeof(struct in_addr)) == 0)) {
                    // Update statistics for the prefix
                    (*prefixes)[i].allocated_addresses++;
                    (*prefixes)[i].utilization = ((*prefixes)[i].allocated_addresses * 100.00) / (*prefixes)[i].max_hosts;
                }
            }
        }

        // Update the list of unique allocated IPs
        *unique_ips = (UniqueAllocatedIP *)realloc(*unique_ips, (*unique_ip_count + 1) * sizeof(UniqueAllocatedIP));
        if (!unique_ips) {
            fprintf(stderr, "Error allocating memory for unique IPs.\n");
            exit(1);
        }
        (*unique_ips)[*unique_ip_count].ip = allocated_ip;
        (*unique_ip_count)++;
    }
}

/**
 * @brief Process a pcap file, updating statistics based on DHCP packets.
 *
 * @param prefixes Pointer to the array of prefixes.
 * @param prefix_count Pointer to the count of prefixes.
 * @param filename Name of the pcap file to process.
 * @param interface Interface name.
 * @param unique_ips Pointer to the array of unique allocated IPs.
 * @param unique_ip_count Pointer to the count of unique allocated IPs.
 */
void processPcapFile(PrefixInfo **prefixes, int *prefix_count, char *filename, char *interface, UniqueAllocatedIP **unique_ips, int *unique_ip_count) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;

    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        exit(1);
    }
    // Set the packet filter
    struct bpf_program fp;
    char filter_exp[] = "udp and port 67";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("Error compiling filter: %s\n", pcap_geterr(handle));
        exit(1);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        printf("Error setting filter: %s\n", pcap_geterr(handle));
        exit(1);
    }
    // Handle only ACKNOWLEDGE packets
    while ((packet = pcap_next(handle, &header))) {
        const u_char *dhcp_pkt = (const u_char *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
        int is_dhcp_ack = 0;
        while(dhcp_pkt < packet + header.len){
            if (*dhcp_pkt == DHCP_OPTION_MSG_TYPE) {         
                dhcp_pkt++;
                if (*dhcp_pkt == 1) { 
                    dhcp_pkt++;
                    if (*dhcp_pkt == DHCPACK) {
                        is_dhcp_ack = 1;
                    }
                }
            }
            dhcp_pkt++;
        }

        if (is_dhcp_ack) {
                processPacket(prefixes, prefix_count, unique_ips, unique_ip_count, packet, header.len, interface);
        }   
    }
    pcap_close(handle);
}

/**
 * @brief Print statistics for each IP prefix.
 *
 * @param prefixes Pointer to the array of prefixes.
 * @param prefix_count Pointer to the count of prefixes.
 */
void printPrefixStats(PrefixInfo **prefixes, int *prefix_count) {
    printf("IP-Prefix Max-hosts Allocated addresses Utilization\n");
    for (int i = 0; i < (*prefix_count); i++) {
        printf("%s %d %d %.2f%%\n", (*prefixes)[i].prefix, (*prefixes)[i].max_hosts,
               (*prefixes)[i].allocated_addresses, (*prefixes)[i].utilization);
    }
    // Check if utilization exceeds 50% and log if not already logged
    for (int i = 0; i < (*prefix_count); i++) {
        if ((*prefixes)[i].utilization > 50 && !(*prefixes)[i].is_logged) {
            syslog(LOG_INFO, "Prefix %s exceeded 50%% of allocations.", (*prefixes)[i].prefix);
            printf("Prefix %s exceeded 50%% of allocations.\n", (*prefixes)[i].prefix);
            (*prefixes)[i].is_logged = true;
        }
    }
}

/**
 * @brief Print live statistics for each IP prefix using ncurses.
 *
 * @param prefixes Pointer to the array of prefixes.
 * @param prefix_count Pointer to the count of prefixes.
 */
void printPrefixStatsLive(PrefixInfo **prefixes, int *prefix_count) {
    printw("IP-Prefix Max-hosts Allocated addresses Utilization\n");
    for (int i = 0; i < (*prefix_count); i++) {
        printw("%s %d %d %.2f%%\n", (*prefixes)[i].prefix, (*prefixes)[i].max_hosts,
               (*prefixes)[i].allocated_addresses, (*prefixes)[i].utilization);
    }
    // Check if utilization exceeds 50% and log if not already logged
    for (int i = 0; i < (*prefix_count); i++) {
        if ((*prefixes)[i].utilization > 50 && !(*prefixes)[i].is_logged) {
            syslog(LOG_INFO, "Prefix %s exceeded 50%% of allocations.", (*prefixes)[i].prefix);
            printf("Prefix %s exceeded 50%% of allocations.\n", (*prefixes)[i].prefix);
            (*prefixes)[i].is_logged = true;
        }
    }
}

int main(int argc, char *argv[]) {
    char *filename = NULL;
    char *interface_name = NULL;
    PrefixInfo *prefixes = NULL;
    int prefix_count = 0;
    UniqueAllocatedIP *unique_ips = NULL;
    int unique_ip_count = 0;
    // Parse arguments
    int opt;
    while ((opt = getopt(argc, argv, "r:i:")) != -1) {
        switch (opt) {
            case 'r':
                filename = optarg;
                break;
            case 'i':
                interface_name = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [-r <filename>] [-i <interface-name>] <ip-prefix> [<ip-prefix> ...]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // Allocate memory for the dynamic array of IP prefixes
    prefixes = (PrefixInfo *)malloc(sizeof(PrefixInfo));
    if (!prefixes) {
        fprintf(stderr, "Chyba při alokaci paměti pro prefixy.\n");
        return 1;
    }

    // Parse remaining arguments (IP prefixes)
    for (int i = optind; i < argc; i++) {
        add_prefix(&prefixes, &prefix_count, argv[i]);
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    // Process packets from pcap file or live capture
    if (filename != NULL) {
        processPcapFile(&prefixes, &prefix_count, filename, interface_name, &unique_ips, &unique_ip_count);
        printPrefixStats(&prefixes, &prefix_count);
    } else {
        initscr(); // Initialize ncurses

        printw("IP-Prefix Max-hosts Allocated addresses Utilization\n");

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle;
        struct pcap_pkthdr header;
        const u_char *packet;
        handle = pcap_open_live(interface_name, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Error opening interface: %s\n", errbuf);
            exit(1);
        }

        // Set the packet filter
        struct bpf_program fp;
        char filter_exp[] = "udp and port 67";
        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            printf("Error compiling filter: %s\n", pcap_geterr(handle));
            return 1;
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            printf("Error setting filter: %s\n", pcap_geterr(handle));
            return 1;
        }
        while (termination_requested == 0) {
            clear();
            packet = pcap_next(handle, &header);
            if (packet) {
                const u_char *dhcp_pkt = (const u_char *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
                int is_dhcp_ack = 0;

                while(dhcp_pkt < packet + header.len){
                    if (*dhcp_pkt == DHCP_OPTION_MSG_TYPE) {         
                        dhcp_pkt++;
                        if (*dhcp_pkt == 1) { 
                            dhcp_pkt++;
                            if (*dhcp_pkt == DHCPACK) {
                                is_dhcp_ack = 1;
                            }
                        }
                    }
                    dhcp_pkt++;
                }
                if (is_dhcp_ack == 1){
                    processPacket(&prefixes, &prefix_count, &unique_ips, &unique_ip_count, packet, header.len, interface_name);

                }
                printPrefixStatsLive(&prefixes, &prefix_count);
                refresh();

            }
        }

        pcap_close(handle);
        endwin(); // End ncurses
    }



    for (int i = 0; i < prefix_count; i++) {
        free(prefixes[i].prefix); // Free memory for each IP prefix
    }
    free(prefixes);

    free(unique_ips);
}