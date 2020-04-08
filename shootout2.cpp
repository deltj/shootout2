/**
 * Shootout2 - 802.11 monitor mode performance evaluator
 *
 * Copyright 2020 Ted DeLoggio <deltj@outlook.com>
 */
#include <array>
#include <condition_variable>
#include <cstdlib>
#include <iostream>
#include <map>
#include <mutex>
#include <queue>
#include <set>
#include <thread>

extern "C" {
#include <getopt.h>
#include <pcap.h>
#include <signal.h>
#include <unistd.h>
}

#include "Packet.h"

bool quit = false;

//  A queue for received packets
std::queue<shootout::Packet> packetQueue;
std::mutex packetQueueMutex;
std::condition_variable packetQueueCv;

//  All hashes
std::set<shootout::PacketHash> allHashes;
std::mutex allHashesMutex;

//  Observed hashes (hits) by interface
std::map<int, std::set<shootout::PacketHash> > hitByInterface;
std::mutex hitByInterfaceMutex;

//  Missed hashes by interface
std::map<int, std::set<shootout::PacketHash> > missByInterface;

//  This structure stores interface information to be passed between the main
//  thread and a worker thread
struct NL80211Interface
{
    std::string name;
    int ifindex;
    std::thread thread;
};

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
void captureThreadFn(std::shared_ptr<NL80211Interface> ifc)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if(ifc == nullptr)
    {
        fprintf(stderr, "Capture thread argument was null\n");
        return;
    }

    printf("Starting capture thread for %d (%s)\n", ifc->ifindex, ifc->name.c_str());

    pcap_t *p = pcap_open_live(ifc->name.c_str(), 800, 1, 20, errbuf);
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
        p.ifindex = ifc->ifindex;

        //  Lock the packetQueue mutex and push the new Packet
        {
            //TODO: add a lock timeout
            std::lock_guard<std::mutex> lk(packetQueueMutex);
            packetQueue.push(p);
        }

        //  Let everyone know there's a new Packet
        packetQueueCv.notify_all();
    }

    pcap_close(p);
}

void statThreadFn()
{
    while(!quit)
    {
        //  Wait for notification that there's a new Packet to process
        //TODO: add a lock timeout
        std::unique_lock<std::mutex> lk(packetQueueMutex);
        packetQueueCv.wait(lk);

        //  The packet queue mutex is locked, process the queue
        while(!packetQueue.empty())
        {
            shootout::Packet p = packetQueue.front();
            packetQueue.pop();

            //  Take note that this hash has been observed
            allHashesMutex.lock();
            allHashes.insert(p.hash);
            allHashesMutex.unlock();

            //  Take note of which interface has observed the hash
            hitByInterfaceMutex.lock();
            hitByInterface[p.ifindex].insert(p.hash);
            hitByInterfaceMutex.unlock();
        }

        lk.unlock();
    }
}

bool interfaceHit(int ifindex, shootout::PacketHash hash)
{
    std::unique_lock<std::mutex> lk(hitByInterfaceMutex);
    std::set<shootout::PacketHash>::const_iterator f = hitByInterface[ifindex].find(hash);
    return f != hitByInterface[ifindex].end();
}

int main(int argc, char *argv[])
{
    srand(time(NULL));
    signal(SIGINT, sighandler);

    std::vector<std::shared_ptr<NL80211Interface> > interfaces;

    //  Configure program options
    struct option long_opts[] =
    {
        { "interface", required_argument, 0, 'i' },
        { 0, 0, 0, 0 }
    };

    const char *optstr = "i:";
    int opt;
    while((opt = getopt_long(argc, argv, optstr, long_opts, &optind)) != -1)
    {
        switch(opt)
        {
        case 'i':
            {
                printf("Using interface %s\n", optarg);

                //  Set up a new interface
                std::shared_ptr<NL80211Interface> ifc =
                        std::make_shared<NL80211Interface>();
                ifc->name = std::string(optarg);
                ifc->ifindex = rand() % 100;

                interfaces.push_back(ifc);
            }
            break;
            
        default:
            fprintf(stderr, "Unrecognized argument %c\n", opt);
            break;
        }
    }

    //TODO: Configure interfaces with netlink

    //  Start a capture thread for each interface
    for(std::vector<std::shared_ptr<NL80211Interface> >::iterator it = interfaces.begin();
            it != interfaces.end(); ++it)
    {
        (*it)->thread = std::thread(captureThreadFn, *it);
    }

    std::thread statThread(statThreadFn);

    while(!quit)
    {
        printf("\n");

        //packetQueueMutex.lock();
        //printf("Packets waiting to be processed: %lu\n", packetQueue.size());
        //packetQueueMutex.unlock();

        allHashesMutex.lock();
        size_t totalPackets = allHashes.size();
        allHashesMutex.unlock();

        printf("Total packets: %lu\n", totalPackets);

        for(std::vector<std::shared_ptr<NL80211Interface> >::iterator iit = interfaces.begin();
                iit != interfaces.end(); ++iit)
        {
            //  Find missed packets for this interface
            //  Note: This loop will not scale well...  find a better solution
            allHashesMutex.lock();
            for(std::set<shootout::PacketHash>::const_iterator hit = allHashes.begin();
                    hit != allHashes.end(); ++hit)
            {
                if(!interfaceHit((*iit)->ifindex, *hit))
                {
                    //  The interface (iit) missed this hash (hit)
                    missByInterface[(*iit)->ifindex].insert(*hit);
                }
            }
            allHashesMutex.unlock();

            printf("Missed packets for %s: %lu (%0.1f)\n", (*iit)->name.c_str(),
                    missByInterface[(*iit)->ifindex].size(),
                    missByInterface[(*iit)->ifindex].size() / (double)totalPackets * 100);
        }

        sleep(1);
    }

    //TODO: join all the capture threads
    statThread.join();

    return EXIT_SUCCESS;
}
