#pragma once
#include "pcapreader.h"

struct TableEntry {
    pcap::pcap_pak_hdr* header;
    char source[INET6_ADDRSTRLEN];
    char destination[INET6_ADDRSTRLEN];
    char info[0xffff];
};
