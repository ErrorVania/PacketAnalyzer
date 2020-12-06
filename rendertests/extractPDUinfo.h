#pragma once
#include <GL/gl3w.h>
#include <GLFW/glfw3.h>
#include <imgui/imgui.h>
#include <imgui/imgui_impl_glfw.h>
#include <imgui/imgui_impl_opengl3.h>
#include <iostream>
#include <sstream>
#include <string>
#include <iomanip>
#include <Windows.h>
#include <WS2tcpip.h>
#include "pcapreader/structs.h"

#include "pcapreader/reader_struct.h"



std::string tomac(uint8_t* mac) {
    std::ios_base::fmtflags f(std::cout.flags());

    std::stringstream b;
    for (int i = 0; i < 6; i++) {
        b << std::hex << (unsigned)*(mac + i);
        if (i <= 4) b << ":";
    }
    std::cout.flags(f);
    return b.str();

}
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




std::string getSource(const pcap::pcap_pak_hdr* pcaphdr) {

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
std::string getDest(const pcap::pcap_pak_hdr* pcaphdr) {
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