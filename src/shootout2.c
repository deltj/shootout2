/*
 * shootout2 - 802.11 monitor mode performance evaluator
 *
 * Copyright 2024 Ted DeLoggio <deltj@outlook.com>
 */
#include <stdio.h>
#include <stdlib.h>

#include <getopt.h>
#include <glib.h>
#include <libmnl/libmnl.h>
//#include <linux/if.h>
#include <linux/nl80211.h>
#include <ncurses.h>
#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>

#define MAX_INTERFACES 100
#define MAX_IF_NAME_LEN 52

struct wifi_interface {
    char ifname[MAX_IF_NAME_LEN];
    int ifindex;
    int prev_mode;
    unsigned long long packet_count;
};

bool quit = false;
bool waiting_for_nl80211_family_name = false;
GPtrArray* interfaces = NULL;
int num_interfaces = 0;
struct mnl_socket* nl_route_socket = NULL;
struct mnl_socket* nl_genl_socket = NULL;
int nl80211_family_id = 0;
uint8_t* nl_socket_buffer = NULL;
unsigned int seq = 1;
WINDOW* headwin = NULL;
WINDOW* ifwin = NULL;
time_t start_time;

void wininit() {
    headwin = newwin(2, COLS, 0, 0);
    ifwin = newwin(LINES - 1, COLS, 1, 0);
}

void winexit() {
    delwin(headwin);
    delwin(ifwin);
}

void winupdate() {
    //  Draw header
    werase(headwin);
    wattron(headwin, A_REVERSE);

    time_t curr_time = time(NULL);
    struct tm* tt = localtime(&curr_time);

    /*
       This should end up being 19 characters wide, but gcc emites a
       format-truncation warning if the destination buffer is smaller
       than 69 bytes
    */
    char date_time_str[70];
    memset(date_time_str, 0, 70);
    snprintf(date_time_str, 69, "%04u/%02u/%02u %02d:%02d:%02d",
             (tt->tm_year + 1900) % 10000,
             (tt->tm_mon + 1) % 100,
             tt->tm_mday % 100,
             tt->tm_hour,
             tt->tm_min,
             tt->tm_sec);

    const int delta_seconds = difftime(curr_time, start_time);
    char elapsed_time_str[70];
    memset(elapsed_time_str, 0, 70);
    snprintf(elapsed_time_str, 69, "Elapsed time: %d",
             delta_seconds);

    int fill = COLS - (31 + strlen(elapsed_time_str));
    wprintw(headwin, "Shootout2 - %s%*s%s",
            date_time_str,
            fill, " ",
            elapsed_time_str);
    wattroff(headwin, A_REVERSE);
    wrefresh(headwin);

    //  Draw interface table
    werase(ifwin);
    for (int i = 0; i < num_interfaces; i++) {
        struct wifi_interface* wi = (struct wifi_interface*)g_ptr_array_index(interfaces, i);

        mvwprintw(ifwin, i, 1,  "%d", wi->ifindex);
        mvwprintw(ifwin, i, 5,  "%s", wi->ifname);
        mvwprintw(ifwin, i, 20, "%lu", wi->packet_count);
        //mvwprintw(ifwin, row, 30, "%lu", missByInterface[(*iit)->ifindex].size());
    }

    mvwprintw(ifwin, LINES - 2, 0, "LINES, COLS = %d, %d", LINES, COLS);

    wrefresh(ifwin);
}

void sighandler(int signum) {
    switch (signum) {
    case SIGINT:
        quit = true;
        break;

    default:
        break;
    }
}

int handle_message(const struct nlmsghdr* nlh, int len) {
    //printf("in handle_message\n");

    while (mnl_nlmsg_ok(nlh, len)) {
        printf("received nlmsg_type=%d, nlmsg_len=%d\n", nlh->nlmsg_type, nlh->nlmsg_len);

        switch (nlh->nlmsg_type) {
        case NLMSG_NOOP:
            printf("NLMSG_NOOP\n");
            break;

        case NLMSG_ERROR: {
            const struct nlmsgerr* error = (const struct nlmsgerr*)mnl_nlmsg_get_payload(nlh);
            if (!error->error) {
                printf("Received genl ACK\n");
            } else {
                printf("Received genl error\n");
            }
            seq += 1;
            return MNL_CB_STOP;
        }
        break;

        case NLMSG_DONE:
            printf("NLMSG_DONE\n");
            break;

        case NLMSG_OVERRUN:
            printf("NLMSG_OVERRUN\n");
            break;

        case GENL_ID_CTRL: {
            const struct genlmsghdr* genlh = (const struct genlmsghdr*)mnl_nlmsg_get_payload(nlh);
            printf("GENL_ID_CTRL cmd=%u, version=%u\n", genlh->cmd, genlh->version);

            if (genlh->cmd == CTRL_CMD_NEWFAMILY) {
                struct nlattr* attr;
                mnl_attr_for_each(attr, nlh, sizeof(*genlh)) {
                    switch (mnl_attr_get_type(attr)) {
                    case CTRL_ATTR_FAMILY_ID:
                        if (waiting_for_nl80211_family_name) {
                            nl80211_family_id = mnl_attr_get_u32(attr);
                            waiting_for_nl80211_family_name = false;
                            printf("nl80211_family_id=%d\n", nl80211_family_id);
                        }
                        break;

                    default:
                        break;
                    }
                }
            }
        }
        break;

        default:
            break;
        }

        nlh = mnl_nlmsg_next(nlh, &len);
    }

    return MNL_CB_OK;
}

void handle_response(struct mnl_socket* sock) {
    //printf("in handle_response\n");

    int ret;

    int len = 0;
    while ((len = mnl_socket_recvfrom(sock, nl_socket_buffer, MNL_SOCKET_BUFFER_SIZE)) > 0) {
        printf("received %d\n", len);

        const struct nlmsghdr* nlh = (const struct nlmsghdr*)nl_socket_buffer;
        ret = handle_message(nlh, len);
        if (ret <= MNL_CB_STOP) {
            break;
        }
    }

    printf("Done handling response\n");
}

int get_nl80211_family_id() {
    struct nlmsghdr* nlh = mnl_nlmsg_put_header(nl_socket_buffer);
    struct genlmsghdr* genlh = (struct genlmsghdr*)mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
    unsigned int portid = mnl_socket_get_portid(nl_genl_socket);

    nlh->nlmsg_type = GENL_ID_CTRL;
    nlh->nlmsg_pid = portid;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = seq;
    genlh->cmd = CTRL_CMD_GETFAMILY;
    genlh->version = 2;
    mnl_attr_put_strz(nlh, CTRL_ATTR_FAMILY_NAME, NL80211_GENL_NAME);

    if (mnl_socket_sendto(nl_genl_socket, nlh, nlh->nlmsg_len) < 0) {
        fprintf(stderr, "mnl_socket_sendto failed");
        return -1;
    }

    waiting_for_nl80211_family_name = true;
    handle_response(nl_genl_socket);

    return 0;
}

int if_info(const int ifindex) {
    struct nlmsghdr* nlh = mnl_nlmsg_put_header(nl_socket_buffer);
    struct ifinfomsg* ifinfo = (struct ifinfomsg*)mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
    unsigned int portid = mnl_socket_get_portid(nl_route_socket);

    nlh->nlmsg_type = RTM_GETLINK;
    nlh->nlmsg_pid = portid;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = seq;
    ifinfo->ifi_family = AF_UNSPEC;
    ifinfo->ifi_index = ifindex;

    if (mnl_socket_sendto(nl_route_socket, nlh, nlh->nlmsg_len) < 0) {
        fprintf(stderr, "mnl_socket_sendto failed");
        return -1;
    }

    handle_response(nl_route_socket);

    return 0;
}

int if_down(struct wifi_interface* wi) {
    struct nlmsghdr* nlh = mnl_nlmsg_put_header(nl_socket_buffer);
    struct ifinfomsg* ifinfo = (struct ifinfomsg*)mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
    unsigned int portid = mnl_socket_get_portid(nl_route_socket);

    unsigned int change = 0;
    unsigned int flags = 0;
    change |= IFF_UP;
    flags &= ~IFF_UP;

    nlh->nlmsg_type = RTM_NEWLINK;
    nlh->nlmsg_pid = portid;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = seq;
    ifinfo->ifi_family = AF_UNSPEC;
    ifinfo->ifi_index = wi->ifindex;
    ifinfo->ifi_change = change;
    ifinfo->ifi_flags = flags;

    if (mnl_socket_sendto(nl_route_socket, nlh, nlh->nlmsg_len) < 0) {
        fprintf(stderr, "mnl_socket_sendto failed");
        return -1;
    }

    handle_response(nl_route_socket);

    return 0;
}

int if_up(struct wifi_interface* wi) {
    struct nlmsghdr* nlh = mnl_nlmsg_put_header(nl_socket_buffer);
    struct ifinfomsg* ifinfo = (struct ifinfomsg*)mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
    unsigned int portid = mnl_socket_get_portid(nl_route_socket);

    unsigned int change = 0;
    unsigned int flags = 0;
    change |= IFF_UP;
    flags |= IFF_UP;

    nlh->nlmsg_type = RTM_NEWLINK;
    nlh->nlmsg_pid = portid;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = seq;
    ifinfo->ifi_family = AF_UNSPEC;
    ifinfo->ifi_index = wi->ifindex;
    ifinfo->ifi_change = change;
    ifinfo->ifi_flags = flags;

    if (mnl_socket_sendto(nl_route_socket, nlh, nlh->nlmsg_len) < 0) {
        fprintf(stderr, "mnl_socket_sendto failed");
        return -1;
    }

    handle_response(nl_route_socket);

    return 0;
}

int set_monitor_mode(struct wifi_interface* wi) {
    struct nlmsghdr* nlh = mnl_nlmsg_put_header(nl_socket_buffer);
    struct genlmsghdr* genlh = (struct genlmsghdr*)mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
    unsigned int portid = mnl_socket_get_portid(nl_genl_socket);

    nlh->nlmsg_type = nl80211_family_id;
    nlh->nlmsg_pid = portid;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = seq;
    genlh->cmd = NL80211_CMD_SET_INTERFACE;
    genlh->version = 2;
    mnl_attr_put_u32(nlh, NL80211_ATTR_IFINDEX, wi->ifindex);
    mnl_attr_put_u32(nlh, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);

    mnl_nlmsg_fprintf(stderr, nl_socket_buffer, nlh->nlmsg_len, sizeof(struct genlmsghdr));

    if (mnl_socket_sendto(nl_genl_socket, nlh, nlh->nlmsg_len) < 0) {
        fprintf(stderr, "mnl_socket_sendto failed");
        return -1;
    }

    handle_response(nl_genl_socket);

    return 0;
}

int set_channel(const int ifindex, const unsigned int freq) {
    struct nlmsghdr* nlh = mnl_nlmsg_put_header(nl_socket_buffer);
    struct genlmsghdr* genlh = (struct genlmsghdr*)mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
    unsigned int portid = mnl_socket_get_portid(nl_genl_socket);

    nlh->nlmsg_type = nl80211_family_id;
    nlh->nlmsg_pid = portid;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = seq;
    genlh->cmd = NL80211_CMD_SET_CHANNEL;
    genlh->version = 0;
    mnl_attr_put_u32(nlh, NL80211_ATTR_IFINDEX, ifindex);
    mnl_attr_put_u32(nlh, NL80211_ATTR_WIPHY_FREQ, freq);

    if (mnl_socket_sendto(nl_genl_socket, nlh, nlh->nlmsg_len) < 0) {
        fprintf(stderr, "mnl_socket_sendto failed");
        return -1;
    }

    handle_response(nl_genl_socket);

    return 0;
}

void* packet_capture_fn(void* arg) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct wifi_interface* wi = (struct wifi_interface*)arg;
    printf("Starting capture thread for %s\n", wi->ifname);

    pcap_t* p = pcap_open_live(wi->ifname, 800, 1, 100, errbuf);
    if (p == NULL) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 0;
    }

    struct pcap_pkthdr* hdr;
    const uint8_t* data;

    while (!quit) {
        /* Wait for a packet from libpcap */
        pcap_next_ex(p, &hdr, &data);

        wi->packet_count++;

        /* Note from the man page for pcap_next_ex:
           The struct pcap_pkthdr and the packet data are not to be freed by
           the caller, and are not guaranteed to be valid after the next call
           to pcap_next_ex(), pcap_next(), pcap_loop(3PCAP), or
           pcap_dispatch(3PCAP); if the code needs them to remain valid, it
           must make a copy of them.
           See: https://www.tcpdump.org/manpages/pcap_next_ex.3pcap.html */


    }

    pcap_close(p);

    printf("Stopping capture thread for %s\n", wi->ifname);

    return 0;
}

/*
void packetCaptureThreadFn(std::shared_ptr<NL80211Interface> ifc)
{
    while(!quit)
    {
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
}*/

int main(int argc, char* argv[]) {
    int retval = EXIT_SUCCESS;
    pthread_t thread_id[MAX_INTERFACES];

    nl_socket_buffer = malloc(MNL_SOCKET_BUFFER_SIZE);
    if (nl_socket_buffer == NULL) {
        retval = EXIT_FAILURE;
        goto end;
    }

    signal(SIGINT, sighandler);

    interfaces = g_ptr_array_new();
    if (interfaces == NULL) {
        retval = EXIT_FAILURE;
        goto cleanup_nl_socket_buffer;
    }

    //  Configure program options
    struct option long_opts[] = {
        { "interface", required_argument, 0, 'i' },
        { 0, 0, 0, 0 }
    };

    const char* optstr = "i:";
    int opt;
    while ((opt = getopt_long(argc, argv, optstr, long_opts, &optind)) != -1) {
        switch (opt) {
        case 'i': {
            //  Check if the interface is real
            const int ifindex = if_nametoindex(optarg);
            if (ifindex > 0) {
                printf("Using interface %s\n", optarg);
                struct wifi_interface* wi = malloc(sizeof(struct wifi_interface));
                memset(wi, 0, sizeof(struct wifi_interface));
                strncpy(wi->ifname, optarg, MAX_IF_NAME_LEN);
                wi->ifindex = if_nametoindex(optarg);
                g_ptr_array_add(interfaces, (gpointer)wi);
                num_interfaces++;
            } else {
                fprintf(stderr, "Interface %s doesn't seem to exist\n", optarg);
                retval = EXIT_FAILURE;
                goto cleanup_interfaces;
            }
        }
        break;

        default:
            fprintf(stderr, "Unrecognized argument %c\n", opt);
            break;
        }
    }

    //  Establish netlink socket connections
    nl_route_socket = mnl_socket_open(NETLINK_ROUTE);
    if (nl_route_socket == NULL) {
        fprintf(stderr, "mnl_socket_open failed");
        retval = EXIT_FAILURE;
        goto cleanup_interfaces;
    }

    if (mnl_socket_bind(nl_route_socket, 0, 4) < 0) {
        fprintf(stderr, "mnl_socket_bind failed");
        retval = EXIT_FAILURE;
        goto cleanup_nl_route_socket;
    }

    nl_genl_socket = mnl_socket_open(NETLINK_GENERIC);
    if (nl_genl_socket == NULL) {
        fprintf(stderr, "mnl_socket_open failed");
        retval = EXIT_FAILURE;
        goto cleanup_nl_route_socket;
    }

    if (mnl_socket_bind(nl_genl_socket, 0, 5) < 0) {
        fprintf(stderr, "mnl_socket_bind failed");
        retval = EXIT_FAILURE;
        goto cleanup_nl_genl_socket;
    }

    printf("Querying for nl80211 family id\n");
    if (get_nl80211_family_id() < 0) {
        fprintf(stderr, "get_nl80211_family_id failed\n");
        goto cleanup_nl_genl_socket;
    }

    //  Configure interfaces
    for (int i = 0; i < num_interfaces; i++) {
        struct wifi_interface* wi = (struct wifi_interface*)g_ptr_array_index(interfaces, i);

        printf("Configuring (%d)%s\n", wi->ifindex, wi->ifname);

        printf("Getting info for %s\n", wi->ifname);
        if_info(wi->ifindex);

        //  Bring the interface down
        printf("Bringing down %s\n", wi->ifname);
        if_down(wi);

        //  Set monitor mode
        printf("Setting %s to monitor mode\n", wi->ifname);
        set_monitor_mode(wi);

        /*printf("Setting %s to channel\n", wi->ifname);
        set_channel(wi->ifindex, 2412);*/

        //  Bring the interface up
        printf("Bringing up %s\n", wi->ifname);
        if_up(wi);

        /* Start capture thread */
        pthread_create(&thread_id[i], NULL, packet_capture_fn, (void*)wi);
    }

    //  Set up ncurses
    initscr();
    noecho();
    wininit();

    /* Remember start time */
    start_time = time(NULL);

    while (!quit) {
        //packetQueueMutex.lock();
        //printf("Packets waiting to be processed: %lu\n", packetQueue.size());
        //packetQueueMutex.unlock();

        //allHashesMutex.lock();
        //size_t totalPackets = allHashes.size();
        //allHashesMutex.unlock();*/

        //       Test duration: %d hours, %d minutes, %d seconds\n", hours, minutes, seconds
        //mvprintw(1, 1, "Unique packets observed: %lu\n", totalPackets);

        //  Iterate interfaces under test
        /*
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


            printf("Missed packets for %s: %lu (%0.1f)\n", (*iit)->name.c_str(),
                    missByInterface[(*iit)->ifindex].size(),
                    missByInterface[(*iit)->ifindex].size() / (double)totalPackets * 100);
        }*/

        winupdate();

        //sleep(1);

        timeout(1000);
        int c = getch();
        switch (c) {
        case KEY_RESIZE:
            winexit();
            wininit();
            break;

        case 'q':
            quit = true;
            break;
        }
    }

    endwin();

    /* Join capture threads */
    for (int i = 0; i < num_interfaces; ++i) {
        pthread_join(thread_id[i], NULL);
    }

cleanup_nl_genl_socket:
    mnl_socket_close(nl_genl_socket);
    nl_genl_socket = NULL;

cleanup_nl_route_socket:
    mnl_socket_close(nl_route_socket);
    nl_route_socket = NULL;

cleanup_interfaces:
    /* This should free all of the struct wifi_interface objects that were malloc()'d? */
    g_ptr_array_free(interfaces, TRUE);
    interfaces = NULL;

cleanup_nl_socket_buffer:
    free(nl_socket_buffer);
    nl_socket_buffer = NULL;

end:
    return retval;
}
