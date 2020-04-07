/**
 * Shootout2 - 802.11 monitor mode performance evaluator
 *
 * Copyright 2020 Ted DeLoggio <deltj@outlook.com>
 */
#include <array>
#include <cstdlib>
#include <map>
#include <mutex>
#include <queue>
#include <set>
#include <thread>

extern "C" {
#include <signal.h>
#include <unistd.h>
#include <pcap.h>
}

#include "Packet.h"

bool quit = false;

//  Set of packets received by all interfaces
shootout::PacketSet allPackets;
std::mutex allPacketsMutex;

//  Packet hashes observed by interfaces
shootout::PacketHashSet hashesByInterface;

void sighandler(int signum)
{
    if(signum == SIGINT)
    {
        quit = true;
    }
}

/**
 * This thread function captures packets from libpcap and adds them to the 
 * packet set.
 */
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

    while(!quit)
    {
        //  Wait for a packet from libpcap
        pcap_next_ex(p, &hdr, &data);

        //  Make a new Packet object for it
        shootout::Packet p;
        p.setData(data, hdr->len);

        //  Add the new Packet to the packet set
        allPacketsMutex.lock();
        allPackets.insert(p);
        allPacketsMutex.unlock();
    }

    pcap_close(p);
}

void statThreadFn()
{
    //  Packets in the packet set newer than this threshold will be ignored. 
    //  The thought here is to allow all interfaces time to receive the same
    //  frame.  This will likely go away once the program is generating its own 
    //  packets.
    //std::chrono::duration<int, std::milli> threshold(10);

    while(!quit)
    {
        allPacketsMutex.lock();

        //  Iterate the packet set
        shootout::PacketSet::iterator it = allPackets.begin();
        while(it != allPackets.end())
        {
            shootout::PacketSet::iterator cit = it++;

            hashesByInterface.insert(it->hash);
        }
        allPacketsMutex.unlock();

        sleep(1);
    }
}

/**
 * This thread prunes old packets from the set
 */
/*
void pruningThreadFn()
{
    //  Packets in the packet set older than this threshold duration will be 
    //  pruned to make room for new packets.  
    std::chrono::duration<int, std::milli> threshold(100);

    while(!quit)
    {
        std::chrono::system_clock::time_point now = std::chrono::system_clock::now();

        //  The packet set must be locked during pruning
        allPacketsMutex.lock();
        shootout::PacketSet::iterator it = allPackets.begin();
        while(it != allPackets.end())
        {
            shootout::PacketSet::iterator cit = it++;

            std::chrono::duration<int, std::milli> ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(now - cit->timeOfReceipt);

            if(ms > threshold)
            {
                allPackets.erase(cit);
            }

        }
        allPacketsMutex.unlock();

        sleep(1);
    }
}
*/

int main(int argc, char *argv[])
{
    signal(SIGINT, sighandler);

    printf("starting threads\n");
    std::thread captureThread(captureThreadFn);
    std::thread statThread(statThreadFn);
    //std::thread pruningThread(pruningThreadFn);

    while(!quit)
    {
        printf("packets in the set: %lu\n", allPackets.size());
        sleep(1);
    }

    captureThread.join();
    statThread.join();
    //pruningThread.join();

    return EXIT_SUCCESS;
}
