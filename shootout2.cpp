/**
 * Shootout2 - 802.11 monitor mode performance evaluator
 *
 * Copyright 2020 Ted DeLoggio <deltj@outlook.com>
 */
#include <array>
#include <cstdlib>
#include <iostream>
#include <map>
#include <mutex>
#include <set>
#include <queue>
#include <thread>

extern "C" {
#include <signal.h>
#include <unistd.h>
#include <pcap.h>
}

#include "Packet.h"

bool quit = false;

//  A queue for received packets
std::queue<shootout::Packet> packetQueue;
std::mutex packetQueueMutex;

//  All hashes
std::set<shootout::PacketHash> allHashes;
std::mutex allHashesMutex;

//  Hashes by interface
std::map<int, std::set<shootout::PacketHash> > hashesByInterface;
std::mutex hashesByInterfaceMutex;

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

        //  Note from the man page for pcap_next_ex:
        //  The struct pcap_pkthdr and the packet data are not to be freed by
        //  the caller, and are not guaranteed to be valid after the next call
        //  to pcap_next_ex(), pcap_next(), pcap_loop(3PCAP), or
        //  pcap_dispatch(3PCAP); if the code needs them to remain valid, it
        //  must make a copy of them.
        //  See: https://www.tcpdump.org/manpages/pcap_next_ex.3pcap.html

        //  Make a new Packet object for the received packet
        shootout::Packet p;
        p.setData(data, hdr->len);

        packetQueueMutex.lock();
        packetQueue.push(p);
        packetQueueMutex.unlock();
    }

    pcap_close(p);
}

void statThreadFn()
{
    while(!quit)
    {
        //TODO: Improve this processing loop with a condition variable, or
        //something else less dumb than this.

        packetQueueMutex.lock();

        if(packetQueue.empty())
        {
            packetQueueMutex.unlock();
            continue;
        }

        shootout::Packet p = packetQueue.front();
        packetQueue.pop();

        packetQueueMutex.unlock();

        //  Take note that this hash has been observed
        allHashesMutex.lock();
        allHashes.insert(p.hash);
        allHashesMutex.unlock();

        //  Take note of which interface has observed the hash
        hashesByInterfaceMutex.lock();
        hashesByInterface[p.ifindex].insert(p.hash);
        hashesByInterfaceMutex.unlock();
    }
}

int main(int argc, char *argv[])
{
    signal(SIGINT, sighandler);

    printf("starting threads\n");
    std::thread captureThread(captureThreadFn);
    std::thread statThread(statThreadFn);

    while(!quit)
    {
        printf("\n");

        packetQueueMutex.lock();
        printf("Packets waiting to be processed: %lu\n", packetQueue.size());
        packetQueueMutex.unlock();

        allHashesMutex.lock();
        printf("All hashes: %lu\n", allHashes.size());
        allHashesMutex.unlock();

        hashesByInterfaceMutex.lock();
        std::map<int, std::set<shootout::PacketHash> >::const_iterator it;
        for(it = hashesByInterface.begin(); it != hashesByInterface.end(); ++it)
        {
            printf("Hashes for interface %d: %lu\n", it->first, it->second.size());
        }
        hashesByInterfaceMutex.unlock();

        sleep(1);
    }

    captureThread.join();
    statThread.join();

    return EXIT_SUCCESS;
}
