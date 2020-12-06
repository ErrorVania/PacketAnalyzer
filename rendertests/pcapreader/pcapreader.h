#pragma once


#include <fstream>
#include <iostream>
#include <vector>
#include "protocols.h"

namespace pcap {
    struct pcap_global_hdr {
        uint32_t magic;
        uint16_t version_major;
        uint16_t version_minor;
        uint32_t thiszone;
        uint32_t sigfigs;
        uint32_t snaplen;
        uint32_t network;
    };
    struct pcap_pak_hdr {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t incl_len;
        uint32_t orig_len;
        uint8_t pdu[];
    };
}



class PcapReader {
private:
    std::ifstream pcapfile;
    uint8_t* data;
    unsigned long size;
    pcap::pcap_global_hdr* ghdr;
    //PDU p;


public:
    PcapReader() {
        data = nullptr;
        //p.payload = nullptr;
        //p.pkhdr = nullptr;
        ghdr = nullptr;
        size = 0;
    }
    void beginRead(std::vector<pcap::pcap_pak_hdr*>* a) {
        a->clear();
        unsigned long offset = sizeof(pcap::pcap_global_hdr);
        pcap::pcap_pak_hdr* pcaphdr = nullptr;
        unsigned int i = 0;
        while (offset < size) {
            pcaphdr = (pcap::pcap_pak_hdr*)(offset + data);

            offset += pcaphdr->incl_len + sizeof(pcap::pcap_pak_hdr);

            //p.payload = data + offset + sizeof(pcap::pcap_pak_hdr);
            

            //p.pkhdr = pcaphdr;
            //protocols::EtherII(p.payload,pcaphdr->incl_len);
            
            a->push_back(pcaphdr);
            i++;
        }
        std::cout << "Read " << i << " PDUs" << std::endl;
        size = i;
    }

    void open(const char* path) {
        pcapfile.open(path, std::ios::binary | std::ios::ate);
        size = pcapfile.tellg();
        pcapfile.seekg(0, std::ios::beg);

        if (data == nullptr) data = (uint8_t*)malloc(size * sizeof(uint8_t)); else data = (uint8_t*)realloc(data, size * sizeof(uint8_t));
        ghdr = (pcap::pcap_global_hdr*)data;

        if (!pcapfile.read((char*)data, size))
        {
            std::cerr << "Couldnt read pcap" << std::endl;
            return;
        }
        pcapfile.close();
    }
    const pcap::pcap_global_hdr* getGHDR() {
        return ghdr;
    }
    ~PcapReader() {
        if (data) {
            free(data);
        }
    }

};