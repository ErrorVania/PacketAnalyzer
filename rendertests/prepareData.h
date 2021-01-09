#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <iomanip>
#include "pcapreader/structs.h"
#include "pcapreader/pcapreader.h"
#include "protoResolv.h"



std::string tomac(uint8_t* mac) {
    std::stringstream b;
    for (int i = 0; i < 6; i++) {
        b << std::hex << (unsigned)*(mac + i);
        if (i <= 4) b << ":";
    }
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


struct TableEntry {
    std::string timestr, src, dst;
    std::vector<std::string> protos;
};

const std::vector<TableEntry> digest(const std::vector<pcap_pak_hdr*>& pdus) {
	std::cout << "Preparing to digest..." << std::endl;
	std::vector<TableEntry> r;

	for (pcap_pak_hdr* pcaphdr : pdus) {
        TableEntry te;
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
			te.src = getSource(pcaphdr);
			te.dst = getDest(pcaphdr);
		}

        //Unravel protocol stack
        {
            std::map<uint16_t, std::string> x;
            protosL2(x);
            eth_hdr* e = (eth_hdr*)&pcaphdr->pdu;
            uint16_t ethertype = ntohs(e->ethertype);
            te.protos.push_back("EtherII");

            bool dobreak = false;

            if (ethertype >= 1536) {
                te.protos.push_back(x[ethertype]);
                switch (ethertype) {
                case 0x0800: //IPv4
                    //What proto does IPv4 carry?
                    {
                        ip_hdr* ip = (ip_hdr*)&e->payload;
                        uint8_t ipproto = ip->proto;
                        switch (ipproto) {
                        case IPPROTO_TCP:
                            te.protos.push_back("TCP");
                            break;
                        
                        case IPPROTO_UDP:
                            te.protos.push_back("UDP");
                            break;
                        }
                    }
                    break;

                case 0x86DD: //IPv6
                    {
                        ip6_hdr* ip6 = (ip6_hdr*)&e->payload;
                        uint8_t ipproto = ip6->next_header;
                        switch (ipproto) {
                        case IPPROTO_TCP:
                            te.protos.push_back("TCP");
                            break;

                        case IPPROTO_UDP:
                            te.protos.push_back("UDPs");
                            break;
                        }
                    }
                break;

                default:
                    std::stringstream b;
                    b << "0x" << std::hex << ethertype;
                    te.protos.push_back(b.str());
                    break;
                }
            }
            else {
                std::stringstream b;
                b << "0x" << std::hex << ethertype;
                te.protos.push_back(b.str());
            }
        }




        r.push_back(te);
	}





    std::cout << r.size() << std::endl;





	return r;
}