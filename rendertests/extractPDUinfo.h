#pragma once
#include <iostream>
#include <sstream>
#include <string>
#include <iomanip>
#include <Windows.h>
#include <WS2tcpip.h>
#include "pcapreader/structs.h"
#include "protoResolv.h"
#include "prepareData.h"


std::string toip(const in_addr* ip) {
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ip, str, INET_ADDRSTRLEN);
    return std::string(str);
}

std::string toip6(const in6_addr* ip) {
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ip, str, INET6_ADDRSTRLEN);
    return std::string(str);
}

std::string lastProtoL2(const pcap_pak_hdr* pcaphdr) {
    static Resolver r;
    
    std::string proto;
    
    const uint8_t* pcap_payload = pcaphdr->pdu;
    eth_hdr* ethernet_header = (eth_hdr*)pcap_payload;
    auto ethtype = ntohs(ethernet_header->ethertype);
    

    if (r.L2->find(ethtype) == r.L2->end())
    {
        std::stringstream sstream;
        sstream << "0x" << std::hex << ethtype;
        proto = sstream.str();
    }
    else {
        proto = r.L2->operator[](ethtype);
    }

    return proto;
}
std::string getSource(const pcap_pak_hdr* pcaphdr) {

    const uint8_t* payload = pcaphdr->pdu;

    eth_hdr* e = (eth_hdr*)payload;
    ip_hdr* ip4 = (ip_hdr*)&e->payload;
    ip6_hdr* ip6 = (ip6_hdr*)&e->payload;
    auto ethtype = ntohs(e->ethertype);

    switch (ethtype) {
    case 0x0800: //IPv4
        return toip(&ip4->src);
        break;

    case 0x86DD: //IPv6
        return toip6(&ip6->src);
        break;

    default:
        return tomac(e->smac);
        break;
    }
}
std::string getDest(const pcap_pak_hdr* pcaphdr) {
    const uint8_t* payload = pcaphdr->pdu;

    eth_hdr* e = (eth_hdr*)payload;
    ip_hdr* ip4 = (ip_hdr*)&e->payload;
    ip6_hdr* ip6 = (ip6_hdr*)&e->payload;
    auto ethtype = ntohs(e->ethertype);

    switch (ethtype) {
    case 0x0800: //IPv4
        return toip(&ip4->dst);
        break;

    case 0x86DD: //IPv6
        return toip6(&ip6->dst);
        break;

    default:
        return tomac(e->dmac);
        break;
    }
}