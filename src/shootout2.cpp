/**
 * Shootout2 - 802.11 monitor mode performance evaluator
 *
 * Copyright 2020 Ted DeLoggio <deltj@outlook.com>
 */
#include <array>
#include <condition_variable>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <queue>
#include <set>
#include <thread>

extern "C" {
#include <getopt.h>
#include <ncurses.h>
#include <pcap.h>
#include <signal.h>
#include <unistd.h>

#include <net/if.h>
#include <libmnl/libmnl.h>
#include <netlink/netlink.h>
//#include <netlink/genl/genl.h>
//#include <netlink/genl/ctrl.h>
//#include <linux/nl80211.h>
}

#include "Packet.h"

using namespace std::chrono_literals;

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
void packetCaptureThreadFn(std::shared_ptr<NL80211Interface> ifc)
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

/**
 * This thread function removes packets from the packet queue and updates the 
 * hash lists.
 */
void packetProcessingThreadFn()
{
    while(!quit)
    {
        std::unique_lock<std::mutex> lk(packetQueueMutex);
        packetQueueCv.wait_for(lk, 100ms);

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

/**
 * This function checks whether a hash has been observed by an interface.
 *
 * @param ifindex The interface index to check
 * @param hash The hash to look for
 * @return true if the hash was found, false otherwise
 */
bool interfaceHit(int ifindex, shootout::PacketHash hash)
{
    std::unique_lock<std::mutex> lk(hitByInterfaceMutex);
    std::set<shootout::PacketHash>::const_iterator f = hitByInterface[ifindex].find(hash);
    return f != hitByInterface[ifindex].end();
}

int main(int argc, char *argv[])
{
    int retval = EXIT_SUCCESS;
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
                std::shared_ptr<NL80211Interface> ifc = std::make_shared<NL80211Interface>();
                ifc->name = std::string(optarg);
                ifc->ifindex = if_nametoindex(optarg);

                interfaces.push_back(ifc);
            }
            break;
            
        default:
            fprintf(stderr, "Unrecognized argument %c\n", opt);
            break;
        }
    }

    //TODO: Configure interfaces with netlink

    //  Remember start time
    std::chrono::time_point<std::chrono::system_clock> startTime =
            std::chrono::system_clock::now();

    //  Start a capture thread for each interface
    int ret;
    for(std::vector<std::shared_ptr<NL80211Interface> >::iterator it = interfaces.begin();
            it != interfaces.end(); ++it)
    {
        //struct nl_sock *nlroute_sock = nl_socket_alloc();

        //nl_connect(nlroute_sock, NETLINK_ROUTE);

        struct mnl_socket *nl = NULL;
        nl = mnl_socket_open(NETLINK_ROUTE);
        
        std::cout << "Configuring " << (*it)->name << " (ifindex " << (*it)->ifindex << ")" << std::endl;

        unsigned int change = 0;
        unsigned int flags = 0;
        change |= IFF_UP;
        flags &= ~IFF_UP;

        uint8_t buf[MNL_SOCKET_BUFFER_SIZE];
        struct nlmsghdr *hdr = mnl_nlmsg_put_header(buf);
        struct ifinfomsg *ifinfo = (struct ifinfomsg *)mnl_nlmsg_put_extra_header(hdr, sizeof(struct ifinfomsg));
        hdr->nlmsg_type = RTM_NEWLINK;
        hdr->nlmsg_pid = getpid();
        hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        ifinfo->ifi_family = AF_UNSPEC;
        ifinfo->ifi_index = (*it)->ifindex;
        ifinfo->ifi_change = change;
	    ifinfo->ifi_flags = flags;

        for(int i=0; i<32; i++)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)(buf[i] && 0xff);
            if((i + 1) % 4 == 0) std::cout << std::endl;
        }

        ret = mnl_socket_sendto(nl, hdr, hdr->nlmsg_len);
        std::cout << "ret=" << ret << std::endl;

        sleep(1);
        mnl_socket_close(nl);

        exit(0);

        //unsigned int change = 0;
        //unsigned int flags = 0;
        //change |= IFF_UP;
        //flags &= ~IFF_UP;

        /*struct ifinfomsg ifinfo;
        ifinfo.ifi_family = AF_UNSPEC;
        //ifinfo.ifi_index = (*it)->ifindex;
        ifinfo.ifi_change = change;
	    ifinfo.ifi_flags = flags;*/

        //struct nl_msg *msg = nlmsg_alloc();
        //std::cout << std::hex << "msg=" << msg << std::endl;
        //struct nlmsghdr *hdr = nlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, RTM_NEWLINK, sizeof(struct nlmsghdr), NLM_F_REQUEST);
        //std::cout << std::hex << "hdr=" << hdr << std::endl;
        //struct ifinfomsg *ifi = (struct ifinfomsg *)nlmsg_reserve(msg, sizeof(struct ifinfomsg), 4);
        //ifi->ifi_family = AF_UNSPEC;
        //ifi->ifi_change = change;
        //ifi->ifi_flags = flags;
        //ifi->ifi_index = (*it)->ifindex;
        
        //nlmsg_append(msg,  &ifinfo, sizeof(ifinfo), NLMSG_ALIGNTO);
        //nla_put(msg, IFLA_IFNAME, strlen((*it)->name.c_str()) + 1, (*it)->name.c_str());
        //if(nla_put_string(msg, IFLA_IFNAME, (*it)->name.c_str()) < 0)
        //{
        //    std::cerr << "nla_put_string failed" << std::endl;
        //}

        //char buf[4096];
        //memcpy(buf, msg, 16);
        //for(int i=0; i<16; i++)
        //{
            //std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)(buf[i] && 0xff);
            //if((i + 1) % 4 == 0) std::cout << std::endl;
        //}

        //int nbytes = nl_send_auto(nlroute_sock, msg);
        //std::cout << "nbytes: " << nbytes << std::endl;

        //sleep(2);

        //nlmsg_free(msg);

        //exit(0);


        //struct nl_msg *msg = nlmsg_alloc();
        //genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, genl_ctrl_resolve(sock, "nl80211"), 0, 0, command, 0);
        //nlmsg_free(msg);


        /*
        std::cout << "Setting channel" << std::endl;
        struct nl_msg *mesg = nlmsg_alloc();
        enum nl80211_commands command = NL80211_CMD_SET_WIPHY;
        genlmsg_put(mesg, 0, 0, genl_ctrl_resolve(sckt, "nl80211"), 0, 0, command, 0);
        NLA_PUT_U32(mesg, NL80211_ATTR_IFINDEX, (*it)->ifindex);
        NLA_PUT_U32(mesg, NL80211_ATTR_WIPHY_FREQ, freqMhz);
        ret = nl_send_auto_complete(sckt, mesg);
        nlmsg_free(mesg);

        std::cout << "Setting monitor mode" << std::endl;
        mesg = nlmsg_alloc();
        command = NL80211_CMD_SET_INTERFACE;
        genlmsg_put(mesg, 0, 0, genl_ctrl_resolve(sckt, "nl80211"), 0, 0, command, 0);
        NLA_PUT_U32(mesg, NL80211_ATTR_IFINDEX, (*it)->ifindex);
        NLA_PUT_U32(mesg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);
        ret = nl_send_auto_complete(sckt, mesg);
        nlmsg_free(mesg);
        */

        

        (*it)->thread = std::thread(packetCaptureThreadFn, *it);

        continue;

        //nla_put_failure:
            //nlmsg_free(mesg);
            //printf("PUT Failure\n");        
    }

    //  Start the packet processing thread
    std::thread packetProcessingThread(packetProcessingThreadFn);

    //  Set up ncurses
    initscr();
    noecho();

    int hours = 0;
    int minutes = 0;
    int seconds = 0;
    while(!quit)
    {
        std::chrono::time_point<std::chrono::system_clock> nowTime = 
                std::chrono::system_clock::now();
        std::chrono::seconds elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(nowTime - startTime);
        if(elapsedTime >= 3600s)
        {
            hours = std::chrono::duration_cast<std::chrono::hours>(elapsedTime).count();
            minutes = std::chrono::duration_cast<std::chrono::minutes>(elapsedTime % std::chrono::hours(hours)).count();
            seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsedTime % std::chrono::minutes(minutes)).count();
        }
        else if(elapsedTime >= 60s)
        {
            minutes = std::chrono::duration_cast<std::chrono::minutes>(elapsedTime).count();
            seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsedTime % std::chrono::minutes(minutes)).count();
        }
        else
        {
            seconds = elapsedTime.count();
        }

        //packetQueueMutex.lock();
        //printf("Packets waiting to be processed: %lu\n", packetQueue.size());
        //packetQueueMutex.unlock();

        allHashesMutex.lock();
        size_t totalPackets = allHashes.size();
        allHashesMutex.unlock();

        mvprintw(0, 1, "Test duration: %d hours, %d minutes, %d seconds\n", hours, minutes, seconds);
        mvprintw(1, 1, "Unique packets observed: %lu\n", totalPackets);

        //  Iterate interfaces under test
        int row = 0;
        int rowoffset = 0;
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

            row = 3 + rowoffset++;
            mvprintw(row, 1,  "%d", (*iit)->ifindex);
            mvprintw(row, 5,  "%s", (*iit)->name.c_str());
            mvprintw(row, 20, "%lu", hitByInterface[(*iit)->ifindex].size());
            mvprintw(row, 30, "%lu", missByInterface[(*iit)->ifindex].size());

            /*
            printf("Missed packets for %s: %lu (%0.1f)\n", (*iit)->name.c_str(),
                    missByInterface[(*iit)->ifindex].size(),
                    missByInterface[(*iit)->ifindex].size() / (double)totalPackets * 100);
            */
        }
        refresh();

        sleep(1);
    }

    //TODO: join all the capture threads
    packetProcessingThread.join();

    endwin();
    return retval;
}
