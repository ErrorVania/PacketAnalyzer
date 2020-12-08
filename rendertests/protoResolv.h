#pragma once
#include <map>
#include <string>


void protosL2(std::map<uint16_t,std::string>& m) {

	m[0x0800] = "IPv4";
	m[0x0806] = "ARP";
	m[0x0842] = "Wake-on-LAN";
	m[0x22F0] = "AVTP";
	m[0x22F3] = "IETF TRILL PROTOCOL";
	m[0x22EA] = "Stream Reservation Protocol";
	m[0x6002] = "DEC MOP RC";
	m[0x6003] = "DECnet Phase IV, DNA Routing";
	m[0x6004] = "DEC LAT";
	m[0x8035] = "RARP";
	m[0x809B] = "AppleTalk";
	m[0x80F3] = "AARP";
	m[0x8100] = "IEEE 802.1Q";
	m[0x8102] = "SLPP";
	m[0x8103] = "VLACP";
	m[0x8137] = "IPX";
	m[0x8204] = "QNX Qnet";
	m[0x86DD] = "IPv6";
	m[0x8808] = "Ethernet flow control";
	m[0x8809] = "LACP";
	m[0x8819] = "CobraNet";
	m[0x8847] = "MPLS unicast";
	m[0x8848] = "MPLS multicast";
	m[0x8863] = "PPPoE Discovery Stage";
	m[0x8864] = "PPPoE Session Stage";
	m[0x887B] = "HomePlug 1.0 MME";
	m[0x888E] = "IEEE 802.1X";
	m[0x8892] = "PROFINET Protocol";
	m[0x889A] = "HyperSCSI";
	m[0x88A2] = "ATA over Ethernet";
	m[0x88A4] = "EtherCAT Protocol";
	m[0x88A8] = "Service VLAN tag identifier (S-Tag) on Q-in-Q tunner";
	m[0x88AB] = "Ethernet Powerlink";
	m[0x88B8] = "GOOSE";
	m[0x88B9] = "GSE Management Service";
	m[0x88BA] = "SV";
	m[0x88BF] = "MikroTik RoMON";
	m[0x88CC] = "LLDP";
	m[0x88CD] = "SERCOS III";
	m[0x88E3] = "IEC62439-2";
	m[0x88E5] = "MACsec";
	m[0x88E7] = "PBB";
	m[0x88F7] = "PTP";
	m[0x88F8] = "NC-SI";
	m[0x88FB] = "PRP";
	m[0x8902] = "IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)";
	m[0x8906] = "FCoE";
	m[0x8914] = "FCoE Initialization Protocol";
	m[0x8915] = "RoCE";
	m[0x891D] = "TTE";
	m[0x893a] = "1905.1 IEEE Protocol";
	m[0x892F] = "HSR";
	m[0x9000] = "Ethernet Configuration Testing Protocol";
	m[0x9100] = "VLAN-tagged (IEEE 802.1Q) frame with double tagging";
	m[0xF1C1] = "Redundancy Tag";

}

class Resolver {
public:
	std::map<uint16_t, std::string>* L2;

	Resolver() {
		L2 = new std::map<uint16_t, std::string>;
		protosL2(*L2);
	}
	~Resolver() {
		delete L2;
	}

};