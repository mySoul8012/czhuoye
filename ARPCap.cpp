#include "ARPCap.h"
#include <iostream>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

ARPCap::ARPCap(const std::string& interfaceID, const std::string& logFileName) : interfaceID(interfaceID), logFileName(logFileName) {
    logFile.open(logFileName, std::ios::out | std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Failed to open log file: " << logFileName << std::endl;
    } else {
        std::cout << "Log file opened successfully: " << logFileName << std::endl;
    }
}

ARPCap::~ARPCap() {
    if (handle) {
        pcap_close(handle);
    }
    if (logFile.is_open()) {
        logFile.close();
    }
}

std::string ARPCap::findInterfaceByDescription() {
    PIP_ADAPTER_INFO AdapterInfo;
    DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);

    AdapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof(IP_ADAPTER_INFO));
    if (AdapterInfo == NULL) {
        std::cerr << "Error allocating memory needed to call GetAdaptersinfo" << std::endl;
        return "";
    }

    if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
        AdapterInfo = (IP_ADAPTER_INFO *) realloc(AdapterInfo, dwBufLen);
        if (AdapterInfo == NULL) {
            std::cerr << "Error reallocating memory needed to call GetAdaptersinfo" << std::endl;
            return "";
        }
    }

    if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
        while (pAdapterInfo) {
            if (std::to_string(pAdapterInfo->Index) == interfaceID) {
                std::string interfaceDescription = pAdapterInfo->Description;
                free(AdapterInfo);
                return interfaceDescription;
            }
            pAdapterInfo = pAdapterInfo->Next;
        }
    }
    free(AdapterInfo);
    return "";
}

void ARPCap::startCapturing() {
    char errbuf[PCAP_ERRBUF_SIZE];
    std::string interfaceDescription = findInterfaceByDescription();
    if (interfaceDescription.empty()) {
        std::cerr << "Couldn't find interface with ID: " << interfaceID << std::endl;
        return;
    }

    std::cout << "Using interface description: " << interfaceDescription << std::endl;

    pcap_if_t *alldevs;
    pcap_if_t *d;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return;
    }

    for (d = alldevs; d; d = d->next) {
        if (d->description && interfaceDescription == d->description) {
            handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf);
            if (handle == nullptr) {
                std::cerr << "Couldn't open device: " << errbuf << std::endl;
                pcap_freealldevs(alldevs);
                return;
            }

            std::cout << "Using device: " << d->name << std::endl;
            break;
        }
    }

    pcap_freealldevs(alldevs);

    if (handle) {
        // Set filter to capture only ARP packets
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, "arp", 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Couldn't parse filter: " << pcap_geterr(handle) << std::endl;
            return;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Couldn't install filter: " << pcap_geterr(handle) << std::endl;
            return;
        }

        pcap_loop(handle, 0, ARPCap::processPacket, reinterpret_cast<u_char*>(this));
    }
}

void ARPCap::processPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    ARPCap* instance = reinterpret_cast<ARPCap*>(args);
    instance->parseARPPacket(packet, header);
}

void ARPCap::parseARPPacket(const u_char *packet, const struct pcap_pkthdr *header) {
    const struct ether_header* ethernetHeader = reinterpret_cast<const struct ether_header*>(packet);
    if (ntohs(ethernetHeader->ether_type) != ETHERTYPE_ARP) {
        return;
    }

    const struct ether_arp* arpPacket = reinterpret_cast<const struct ether_arp*>(packet + sizeof(struct ether_header));

    char srcIP[INET_ADDRSTRLEN];
    char dstIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arpPacket->arp_spa, srcIP, sizeof(srcIP));
    inet_ntop(AF_INET, arpPacket->arp_tpa, dstIP, sizeof(dstIP));

    auto formatMAC = [](const u_char *mac) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (int i = 0; i < 6; ++i) {
            if (i != 0) {
                oss << ":";
            }
            oss << std::setw(2) << static_cast<int>(mac[i]);
        }
        return oss.str();
    };

    std::string srcMAC = formatMAC(arpPacket->arp_sha);
    std::string dstMAC = formatMAC(arpPacket->arp_tha);

    // Format the time correctly
    char timeString[64];
    std::time_t packetTime = header->ts.tv_sec;
    std::strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", std::localtime(&packetTime));

    std::string operation;
    switch (ntohs(arpPacket->ea_hdr.ar_op)) {
        case 1:
            operation = "ARP Request";
            break;
        case 2:
            operation = "ARP Reply";
            break;
        default:
            operation = "Unknown";
            break;
    }

    std::stringstream logMessage;
    logMessage << "Time: " << timeString << "\n"
               << "Source IP: " << srcIP << "\n"
               << "Source MAC: " << srcMAC << "\n"
               << "Destination IP: " << dstIP << "\n"
               << "Destination MAC: " << dstMAC << "\n"
               << "ARP Operation: " << operation << "\n\n";

    std::cout << logMessage.str();
    logPacket(logMessage.str());
}

void ARPCap::logPacket(const std::string& logMessage) {
    if (logFile.is_open()) {
        logFile << logMessage;
    } else {
        std::cerr << "Log file is not open, cannot log message." << std::endl;
    }
}
