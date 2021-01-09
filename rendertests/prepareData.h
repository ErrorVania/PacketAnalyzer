#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <WS2tcpip.h>
#include <map>
#include "pcapreader/structs.h"
#include "pcapreader/pcapreader.h"
#include "protoResolv.h"

struct TableEntry {
	char* timestr, *src, *dst;
	unsigned incl_len;
    std::vector<const char*> protos;
};

std::string tomac(uint8_t* mac) {
    std::stringstream b;
    for (int i = 0; i < 6; i++) {
        b << std::hex << (unsigned)*(mac + i);
        if (i <= 4) b << ":";
    }
    return b.str();

}




const std::vector<TableEntry> digest(const std::vector<pcap_pak_hdr*>& pdus) {
	std::cout << "Preparing to digest..." << std::endl;
	std::vector<TableEntry> r;

	TableEntry te;
	for (pcap_pak_hdr* pcaphdr : pdus) {

		//get time
		{
			time_t nowtime = ((timeval*)pcaphdr)->tv_sec;
			tm nowtm;
			localtime_s(&nowtm, &nowtime);
			char b[20];
			strftime(b, 20, "%d.%m.%Y %H:%M:%S", &nowtm);
			te.timestr = b;
		}

		//get route
		{
            const uint8_t* payload = pcaphdr->pdu;

            eth_hdr* e = (eth_hdr*)payload;
            ip_hdr* ip4 = (ip_hdr*)&e->payload;
            ip6_hdr* ip6 = (ip6_hdr*)&e->payload;
            auto ethtype = ntohs(e->ethertype);

            char src[INET6_ADDRSTRLEN];
            char dst[INET6_ADDRSTRLEN];

            switch (ethtype) {
            case 0x0800: //IPv4
                //char src[INET_ADDRSTRLEN];
                //char dst[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, ip4, src, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET, ip4, dst, INET6_ADDRSTRLEN);

                te.src = src;
                te.dst = dst;

                break;

            case 0x86DD: //IPv6
                //char src[INET6_ADDRSTRLEN];
                //char dst[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, ip6, src, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, ip6, dst, INET6_ADDRSTRLEN);

                te.src = src;
                te.dst = dst;

                break;

            default:
                te.src = (char*)tomac(e->smac).c_str();
                te.dst = (char*)tomac(e->dmac).c_str();
                break;
            }
		}
        te.incl_len = pcaphdr->incl_len;


        //Unravel protocol stack
        {
            std::map<uint16_t, std::string> x;
            eth_hdr* e = (eth_hdr*)pcaphdr->pdu;
            protosL2(x);
            te.protos.push_back("EtherII");
            if (e->ethertype >= 1536) {
                te.protos.push_back(x[e->ethertype].c_str());



            }
        }





	}












	return r;
}