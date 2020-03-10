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
}

#include "Packet.h"

bool quit = false;
std::queue<shootout::Packet> packetQueue;
std::mutex packetQueueMutex;
std::set<std::array<uint8_t, 32>> hashSet;
std::mutex hashSetMutex;

void sighandler(int signum)
{
    if(signum == SIGINT)
    {
        quit = true;
    }
}

//  used for testing only
void fakePacketThread()
{
    while(!quit)
    {
        //  Generate random data to test packet hashing
        uint8_t randomData[1000];
        for(int i=0; i<1000; ++i)
        {
            randomData[i] = rand() * 255;
        }
        shootout::Packet p;
        p.ifindex = 1;
        p.setData(randomData, 1000);

        /*
        uint8_t hash[32];
        p.getHash(hash);
        for(int i=0; i<32; ++i)
            printf("%02X", hash[i]);
        printf("\n");
        */

        packetQueueMutex.lock();
        packetQueue.push(p);
        packetQueueMutex.unlock();
    }
}

void packetBinner()
{
    while(!quit)
    {
        packetQueueMutex.lock();
        if(packetQueue.size() > 0)
        {
            shootout::Packet p = packetQueue.front();

            std::array<uint8_t, 32> hash;
            //uint8_t hash[32];
            p.getHash(hash.data());
            /*
            for(int i=0; i<32; ++i)
                printf("%02X", hash[i]);
            printf("\n");
            */

            hashSetMutex.lock();
            //TODO: make separate sets for each wifi card
            hashSet.insert(hash);
            hashSetMutex.unlock();

            packetQueue.pop();
        }
        packetQueueMutex.unlock();
    }
}

int main(int argc, char *argv[])
{
    signal(SIGINT, sighandler);

    std::thread packetThread(fakePacketThread);
    std::thread binnerThread(packetBinner);

    while(!quit)
    {
        packetQueueMutex.lock();
        printf("packetQueue size: %lu\n", packetQueue.size());
        packetQueueMutex.unlock();

        hashSetMutex.lock();
        printf("hashSet size: %lu\n", hashSet.size());
        hashSetMutex.unlock();

        sleep(1);
    }
    packetThread.join();
    binnerThread.join();

    return EXIT_SUCCESS;
}
