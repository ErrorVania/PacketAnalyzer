#pragma once
#include "pcapreader/pcapreader.h"

struct readerstruct {
    int pduid;
    char source[INET6_ADDRSTRLEN];
    char destination[INET6_ADDRSTRLEN];
    pcap::pcap_pak_hdr* header;
    char info[0xffff];
};
