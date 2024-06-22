#ifndef ARPCAP_H
#define ARPCAP_H

#include <pcap.h>
#include <string>
#include <fstream>

class ARPCap {
public:
    ARPCap(const std::string& interfaceID, const std::string& logFileName);
    ~ARPCap();
    void startCapturing();
    static void processPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

private:
    pcap_t *handle;
    std::ofstream logFile;
    std::string interfaceID;
    std::string logFileName;
    void parseARPPacket(const u_char *packet, const struct pcap_pkthdr *header);
    void logPacket(const std::string& logMessage);

    struct ether_header {
        u_char ether_dhost[6]; // Destination host address
        u_char ether_shost[6]; // Source host address
        u_short ether_type;    // IP? ARP? RARP? etc
    };

    struct arphdr {
        u_short ar_hrd; // Format of hardware address.
        u_short ar_pro; // Format of protocol address.
        u_char ar_hln;  // Length of hardware address.
        u_char ar_pln;  // Length of protocol address.
        u_short ar_op;  // ARP opcode (command).
    };

    struct ether_arp {
        struct arphdr ea_hdr;       // fixed-size header
        u_char arp_sha[6];          // sender hardware address
        u_char arp_spa[4];          // sender protocol address
        u_char arp_tha[6];          // target hardware address
        u_char arp_tpa[4];          // target protocol address
    };

    static const u_short ETHERTYPE_ARP = 0x0806; // ARP protocol
    std::string findInterfaceByDescription();
};

#endif // ARPCAP_H
