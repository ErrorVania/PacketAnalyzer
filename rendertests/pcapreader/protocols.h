#pragma once
#include <iostream>
#include <ios>
#include <bitset>
#include <sstream>
#include <iomanip>
#include "structs.h"
#include <WS2tcpip.h>
#include <string>

#define INET6_ADDRSTRLEN 46
#define INET4_ADDRSTRLEN 16

typedef unsigned uint;

std::string tomac(uint8_t* mac) {
    std::ios_base::fmtflags f(std::cout.flags());

    std::stringstream b;
    for (int i = 0; i < 6; i++) {
        b << std::hex << (uint)*(mac + i);
        if (i <= 5) b << ":";
    }
    std::cout.flags(f);
    return b.str();
    
}
std::string toip(const in_addr* ip) {
    char str[INET4_ADDRSTRLEN];
    inet_ntop(AF_INET, ip, str, INET4_ADDRSTRLEN);
    return std::string(str);
}

std::string toip6(const in6_addr* ip) {
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ip, str, INET6_ADDRSTRLEN);
    return std::string(str);
}



namespace protocols {

    void UDP(uint8_t* buf, uint32_t calcdsize) {
        udp_hdr* udphdr = (udp_hdr*)buf;
        std::cout << "(UDP: Port " << ntohs(udphdr->srcport) << " > " << ntohs(udphdr->dstport) << ", Payload: " << ntohs(udphdr->length) - sizeof(udp_hdr) << " bytes)";
    }
    void TCP(uint8_t* buf, const ip_hdr* iphdr) {
        tcp_hdr* tcphdr = (tcp_hdr*)buf;
        uint hdrlen = (tcphdr->data_offset >> 4)*4;
        std::bitset<8> fl(tcphdr->flags);
        std::cout << "(TCP: Port " << ntohs(tcphdr->src_port) << " > " << ntohs(tcphdr->dst_port) << " Header Length: " << hdrlen << ", Flags:[" << fl << "], Payload: " << (ntohs(iphdr->total_len) - iphdr->ihl*4 - hdrlen) << " bytes)";

    }
    void TCP(uint8_t* buf, const ip6_hdr* iphdr) {
        tcp_hdr* tcphdr = (tcp_hdr*)buf;
        uint hdrlen = (tcphdr->data_offset >> 4)*4;
        std::bitset<8> fl(tcphdr->flags);
        std::cout << "(TCP: Port " << ntohs(tcphdr->src_port) << " > " << ntohs(tcphdr->dst_port) << ", Flags:[" << fl << "], Payload: " << (ntohs(iphdr->length) - hdrlen) << " bytes)";

    }


    void ICMP(uint8_t* buf, const ip_hdr* iphdr) {
        icmp_hdr* icmphdr = (icmp_hdr*)buf;
        std::cout << "(ICMP: Type " << (int)icmphdr->type << " Code " << (int)icmphdr->code << ", Rest: " << ntohl(icmphdr->rest) << ", Payload: " << (ntohs(iphdr->total_len) - iphdr->ihl*4 - sizeof(icmp_hdr)) << " bytes)";
    }
    void ICMP(uint8_t* buf, const ip6_hdr* iphdr) {
        icmp_hdr* icmphdr = (icmp_hdr*)buf;
        std::cout << "(ICMP: Type " << (int)icmphdr->type << " Code " << (int)icmphdr->code << ", Rest: " << ntohl(icmphdr->rest) << ", Payload: " << (ntohs(iphdr->length) - sizeof(icmp_hdr)) << " bytes)";
    }

    void IPv4(uint8_t* buf, uint32_t calcdsize) {

        ip_hdr* iphdr = (ip_hdr*)buf;
        std::cout << "(IPv4: " << toip(&iphdr->src) << " > " << toip(&iphdr->dst) << ")";

        switch (iphdr->proto) {
            case IPPROTO_UDP:
                std::cout << "|";
                UDP(buf + iphdr->ihl*4);
                break;
            case IPPROTO_TCP:
                std::cout << "|";
                TCP(buf + iphdr->ihl*4, iphdr);
                break;
            case IPPROTO_ICMP:
                std::cout << "|";
                ICMP(buf + iphdr->ihl*4,iphdr);
                break;
            default:
                std::cout << "| " << iphdr->proto;
                break;
        }

    }
    void IPv6(uint8_t* buf, uint32_t calcdsize) {
        ip6_hdr* iphdr = (ip6_hdr*)buf;

        std::cout << "(IPv6: " << toip6(&iphdr->src) << " > " << toip6(&iphdr->dst) << ")";

        switch (iphdr->next_header) {
            case IPPROTO_UDP:
                std::cout << "|";
                UDP(buf + sizeof(ip6_hdr));
                break;
            case IPPROTO_TCP:
                std::cout << "|";
                TCP(buf + sizeof(ip6_hdr), iphdr);
                break;
            case 0x3A: //ICMP6
                std::cout << "|";
                ICMP(buf + sizeof(ip6_hdr), iphdr);
                break;
            default:
                std::cout << "| " << iphdr->next_header;
                break;
        }
    }


    void ARP(uint8_t* buf, uint32_t calcdsize) {
        arp_hdr* arphdr = (arp_hdr*)buf;
        std::cout << "(ARP: ";
        if (htons(arphdr->htype) == 1)
            std::cout << "Ethernet "; //all other are irrelevant
        if (htons(arphdr->oper) == 1)
            std::cout << "Request, ";
        else
            std::cout << "Reply,   ";

        std::cout << tomac(arphdr->senderhardwareaddr) << "/" << toip((in_addr*)&arphdr->senderprotoaddr) << " > " << tomac(arphdr->targethardwareaddr) << "/" << toip((in_addr*)&arphdr->targetprotoaddr) << ")";
    }





    void EtherII(uint8_t* buf, uint32_t incl_size) {
        eth_hdr* ethernet_header = (eth_hdr*)buf;
        uint16_t ethtype = ntohs(ethernet_header->ethertype);
        uint32_t newsize = incl_size - sizeof(eth_hdr);

        std::cout << "(Ether: " << tomac(ethernet_header->smac) << " > " << tomac(ethernet_header->dmac) << ")";



        if (ethtype <= 1500) { //ethtype is size
            std::cout << "|" << "(Raw: " << ethtype << " bytes)" << std::endl;
            return;
        }


        if (ethtype >= 1536) { //ethtype is proto
            std::cout << "|";
            switch (ethtype) {
                case 0x0800:
                    IPv4((uint8_t*)&ethernet_header->payload,newsize);
                    break;
                case 0x0806:
                    ARP((uint8_t*)&ethernet_header->payload, newsize);
                    break;
                case 0x86DD:
                    IPv6((uint8_t*)&ethernet_header->payload, newsize);
                    break;
                default:
                    std::cout << " " << std::hex << "0x" << ethtype << std::dec;
            }

        } else {
            std::cout << "??? " << ethtype;
        }
        std::cout << std::endl;
    
    
    }
}