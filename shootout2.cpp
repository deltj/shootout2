/**
 * Shootout2 - 802.11 monitor mode performance evaluator
 *
 * Copyright 2020 Ted DeLoggio <deltj@outlook.com>
 */
#include <array>
#include <mutex>
#include <queue>
#include <set>
#include <thread>

#include <cstdlib>

extern "C" {
#include <signal.h>
#include <unistd.h>
#include <pcap.h>
}

#include "Packet.h"

bool quit = false;
std::mutex packetSetMutex;
shootout::PacketSet packetSet;

void sighandler(int signum)
{
    if(signum == SIGINT)
    {
        quit = true;
    }
}

void captureThreadFn()
{
    char errbuf[PCAP_ERRBUF_SIZE];

    printf("pcap_open_live\n");
    pcap_t *p = pcap_open_live("wlp7s0", 800, 1, 20, errbuf);
    if(p == NULL)
    {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return;
    }

    struct pcap_pkthdr *hdr;
    const uint8_t *data;
    //uint8_t hash[32];

    while(!quit)
    {
        pcap_next_ex(p, &hdr, &data);

        shootout::Packet p;
        p.setData(data, hdr->len);

        /*
        p.getHash(hash);
        for(int i=0; i<32; ++i)
            printf("%02X", hash[i]);
        printf("\n");
        */

        packetSetMutex.lock();
        packetSet.insert(p);
        packetSetMutex.unlock();
    }

    pcap_close(p);
}

int main(int argc, char *argv[])
{
    signal(SIGINT, sighandler);

    printf("starting thread\n");
    std::thread testThread(captureThreadFn);
    while(!quit)
    {
        printf("packets: %lu\n", packetSet.size());
        sleep(1);
    }
    testThread.join();

    return EXIT_SUCCESS;
}
