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
