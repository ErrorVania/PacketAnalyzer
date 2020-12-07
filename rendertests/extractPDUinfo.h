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
std::string lastProtoL2(const pcap::pcap_pak_hdr* pcaphdr) {
    std::string proto;
    
    const uint8_t* pcap_payload = pcaphdr->pdu;
    eth_hdr* ethernet_header = (eth_hdr*)payload;
    auto ethtype = ntohs(ethernet_header->ethertype)
    switch (ethtype) { //Layer 2
        case 0x0800: //IPv4
            proto = "IPv4";
            break;
            
		case 0x0806: //ARP
            proto = "ARP";
            break;
            
        case 0x0842: //Wake-On-LAN
            proto = "Wake-on-LAN";
            break;
        
        case 0x22F0: //AVTP
            proto = "AVTP";
            break;

        case 0x22F3: //IETF TRILL PROTOCOL
            proto = "IETF TRILL PROTOCOL";
            break;

        case 0x22EA: //Stream Reservation Protocol
            proto = "Stream Reservation Protocol";
            break;

        case 0x6002: //DEC MOP RC
            proto = "DEC MOP RC";
            break;

        case 0x6003: //DECnet Phase IV, DNA Routing
            proto = "DECnet Phase IV, DNA Routing";
            break;

        case 0x6004: //DEC LAT
            proto = "DEC LAT";
            break;
            
        case 0x8035: //RARP
            proto = "RARP";
            break;

        case 0x809B: //AppleTalk
            proto = "AppleTalk";
            break;

        case 0x80F3: //AppleTalk ARP
            proto = "AppleTalk ARP";
            break;
            
        case 0x8100: //IEEE 802.1Q
            proto = "IEEE 802.1Q";
            break;

        case 0x8102: //SLPP
            proto = "SLPP";
            break;

        case 0x8103: //VLACP
            proto = "VLACP";
            break;

        case 0x8137: //IPX
            proto = "IPX";
            break;
        
        case 0x8204: //QNX Qnet
            proto = "QNX Qnet";
            break;
        
        case 0x86DD: //IPv6
            proto = "IPv6";
            break;
		
        case 0x8808: //Ethernet flow control
            proto = "Ethernet flow control";
            break;

        case 0x8809: //LACP
            proto = "LACP";
            break;
            
        case 0x8819: //CobraNet
            proto = "CobraNet";
            break;

        case 0x8847: //MPLS unicast
            proto = "MPLS unicast";
            break;

        case 0x8848: //MPLS multicast
            proto = "MPLS multicast";
            break;

        case 0x8863: //PPPoE Discovery Stage
            proto = "PPPoE Discovery Stage";
            break;

        case 0x8864: //PPPoE Sessio Stage
            proto = "PPPoE Session Stage";
            break;
        
        case 0x887B: //HomePlug 1.0 MME
            proto = "HomePlug 1.0 MME";
            break;

        case 0x888E: //IEEE 802.1X
            proto = "IEEE 802.1X";
            break;

        case 0x8892: //PROFINET Protocol
            proto = "PROFINET Protocol";
            break;
        
        case 0x889A: //HyperSCSI
            proto = "HyperSCSI";
            break;

        case 0x88A2: //ATA over Ethernet
            proto = "ATA over Ethernet";
            break;

        case 0x88A4: //EtherCAT Protocol
            proto = "EtherCAT Protocol";
            break;
		
        case 0x88A8: //Service VLAN tag identifier (S-Tag) on Q-in-Q tunner
            proto = "Service VLAN tag identifier (S-Tag) on Q-in-Q tunner";
            break;

        case 0x88AB: //Ethernet Powerlink
            proto = "Ethernet Powerlink";
            break;

        case 0x88B8: 	//GOOSE
		    proto = "GOOSE";
		    break;

        case 0x88B9:	//GSE Management Service
		    proto = "GSE Management Service";
		    break;

        case 0x88BA: 	//SV
		    proto = "SV";
		    break;

        case 0x88BF: 	//MikroTik RoMON
		    proto = "MikroTik RoMON";
		    break;

        case 0x88CC: 	//LLDP
		    proto = "LLDP";
		    break;

        case 0x88CD: 	//SERCOS III
		    proto = "SERCOS III";
		    break;

        case 0x88E3: 	//IEC62439-2
		    proto = "IEC62439-2";
		    break;

        case 0x88E5: 	//MACsec
		    proto = "MACsec";
		    break;

        case 0x88E7: 	//IEEE PBB
		    proto = "PBB";
		    break;

        case 0x88F7: 	//PTP
		    proto = "PTP";
		    break;
 
        case 0x88F8: 	//NC-SI
		    proto = "NC-SI";
		    break;

        case 0x88FB: 	//PRP
		    proto = "PRP";
		    break;

        case 0x8902: 	//IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)
		    proto = "IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)";
		    break;

        case 0x8906: 	//FCoE
		    proto = "FCoE";
		    break;

        case 0x8914: 	//FCoE Initialization Protocol
		    proto = "FCoE Initialization Protocol";
		    break;

        case 0x8915: 	//RoCE
		    proto = "RoCE";
		    break;

        case 0x891D: 	//TTE
		    proto = "TTE";
		    break;

        case 0x893a: 	//1905.1 IEEE Protocol
		    proto = "1905.1 IEEE Protocol";
		    break;

        case 0x892F: 	//HSR
		    proto = "HSR";
		    break;

        case 0x9000: 	//Ethernet Configuration Testing Protocol
		    proto = "Ethernet Configuration Testing Protocol";
		    break;

        case 0x9100: 	//VLAN-tagged (IEEE 802.1Q) frame with double tagging
		    proto = "VLAN-tagged (IEEE 802.1Q) frame with double tagging";
		    break;

        case 0xF1C1: 	//Redundancy Tag
		    proto = "Redundancy Tag";
		    break;
            
        default:
            std::stringstream sstream;
            sstream << "0x" << std::hex << ethtype;
            proto = sstream.str();
            break;
    }


    return proto;
}
