/**
 * shootout2 - 802.11 monitor mode performance evaluator
 *
 * Copyright 2024 Ted DeLoggio <deltj@outlook.com>
 */
#include <stdio.h>
#include <stdlib.h>

#include <linux/nl80211.h>
#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <getopt.h>
#include <libmnl/libmnl.h>
#include <ncurses.h>
#include <openssl/evp.h>
#include <pcap/pcap.h>

#include "crc.h"
#include "wifi.h"
#include "hash_table.h"

#define MAX_INTERFACES 100  //  Do I think anyone will try to test more than 100 interfaces?
#define MAX_IF_NAME_LEN 52
#define MAX_WIPHY_NAME_LEN 40
#define HASH_SIZE 32
#define RT_HDR_SIZE 8

/*
 * Structure containing information about interfaces under test
 */
typedef struct wifi_interface {
    char ifname[MAX_IF_NAME_LEN];
    int ifindex;
    uint32_t wiphy;
    char wiphy_name[MAX_WIPHY_NAME_LEN];
    int ai; //  Array index for hash tables and mutexes

    int prev_mode;
    char reg_dom[3];
    unsigned long long packet_count;
    unsigned long long frames_missed;
    float percent_observed;
} wifi_interface_t;

/*
 * Radiotap header structure
 */
struct ieee80211_radiotap_header {
    u_int8_t        it_version;     // set to 0
    u_int8_t        it_pad;
    u_int16_t       it_len;         // entire length
    u_int32_t       it_present;     // fields present
} __attribute__((__packed__));

bool quit = false;
bool waiting_for_nl80211_family_name = false;
bool waiting_for_nl80211_phy = false;
bool waiting_for_nl80211_interface = false;
int num_interfaces = 0;
struct mnl_socket* nl_route_socket = NULL;
struct mnl_socket* nl_genl_socket = NULL;
int nl80211_family_id = 0;
uint8_t* nl_socket_buffer = NULL;
unsigned int seq = 1;
WINDOW* headwin = NULL;
WINDOW* ifwin = NULL;
time_t start_time;
uint32_t tmp_wiphy;
char tmp_wiphy_name[MAX_WIPHY_NAME_LEN];
wifi_interface_t interfaces[MAX_INTERFACES];
hash_table_t *all_packets;
pthread_mutex_t all_packets_mutex;
hash_table_t *interface_packets[MAX_INTERFACES];
pthread_mutex_t interface_packets_mutex[MAX_INTERFACES];

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

    //  This should end up being 19 characters wide, but gcc emites a
    //  format-truncation warning if the destination buffer is smaller
    //  than 69 bytes
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
    //TODO: indicate the driver being used by each interface
    //TODO: allow sorting by: ifindex, ifname, rx count, ...
    werase(ifwin);
    mvwprintw(ifwin, 0, 0, "name                ifidx wiphy phyname hit       miss");
    for (int i = 0; i < num_interfaces; i++) {
        mvwprintw(ifwin, i + 1, 0,  "%s", interfaces[i].ifname);
        mvwprintw(ifwin, i + 1, 20, "%d", interfaces[i].ifindex);
        mvwprintw(ifwin, i + 1, 26, "%u", interfaces[i].wiphy);
        mvwprintw(ifwin, i + 1, 32, "%s", interfaces[i].wiphy_name);
        mvwprintw(ifwin, i + 1, 40, "%llu", interfaces[i].packet_count);
        mvwprintw(ifwin, i + 1, 50, "%llu", interfaces[i].frames_missed);
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
    const char* tmp_str;

    while (mnl_nlmsg_ok(nlh, len)) {
        printf("received nlmsg_type=%d, nlmsg_len=%d\n", nlh->nlmsg_type, nlh->nlmsg_len);

        switch (nlh->nlmsg_type) {
        case NLMSG_NOOP:
            printf("NLMSG_NOOP\n");
            break;

        case NLMSG_ERROR: {
            const struct nlmsgerr* error = (const struct nlmsgerr*)mnl_nlmsg_get_payload(nlh);
            if (error->error == NLE_SUCCESS) {
                printf("Received genl ACK\n");
            } else {
                fprintf(stderr, "Received genl error %d\n", error->error);
                mnl_nlmsg_fprintf(stderr, (void *)nlh, nlh->nlmsg_len, 0);
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
        
        case 35: {
            const struct genlmsghdr* genlh = (const struct genlmsghdr*)mnl_nlmsg_get_payload(nlh);
            printf("35 cmd=%u, version=%u\n", genlh->cmd, genlh->version);

            if (genlh->cmd == 3 && waiting_for_nl80211_phy) {
                mnl_nlmsg_fprintf(stderr, (void *)nlh, len, sizeof(struct genlmsghdr));

                waiting_for_nl80211_phy = false;
                struct nlattr* attr;
                mnl_attr_for_each(attr, nlh, sizeof(*genlh)) {
                    const uint16_t attr_type = mnl_attr_get_type(attr);
                    printf("Attribute type = %u (%s)\n", attr_type, attrnames[attr_type]);

                    switch (attr_type) {

                    case NL80211_ATTR_WIPHY:
                        tmp_wiphy = mnl_attr_get_u32(attr);
                        printf("WIPHY = %u\n", tmp_wiphy);
                        break;

                    case NL80211_ATTR_WIPHY_NAME:
                        tmp_str = mnl_attr_get_str(attr);
                        memset(tmp_wiphy_name, 0, MAX_WIPHY_NAME_LEN);
                        strncpy(tmp_wiphy_name, tmp_str, MAX_WIPHY_NAME_LEN);
                        printf("WIPHY_NAME = %s\n", tmp_str);
                        break;
                    
                    case NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX:
                        break;

                    default:
                        break;
                    }
                }
            } else if (genlh->cmd == 7 && waiting_for_nl80211_interface) {
                mnl_nlmsg_fprintf(stderr, (void *)nlh, len, sizeof(struct genlmsghdr));

                waiting_for_nl80211_interface = false;
                struct nlattr* attr;
                mnl_attr_for_each(attr, nlh, sizeof(*genlh)) {
                    const uint16_t attr_type = mnl_attr_get_type(attr);
                    printf("Attribute type = %u (%s)\n", attr_type, attrnames[attr_type]);

                    switch (attr_type) {

                    case NL80211_ATTR_WIPHY:
                        tmp_wiphy = mnl_attr_get_u32(attr);
                        printf("WIPHY = %u\n", tmp_wiphy);
                        break;

                    case NL80211_ATTR_WIPHY_NAME:
                        tmp_str = mnl_attr_get_str(attr);
                        memset(tmp_wiphy_name, 0, MAX_WIPHY_NAME_LEN);
                        strncpy(tmp_wiphy_name, tmp_str, MAX_WIPHY_NAME_LEN);
                        printf("WIPHY_NAME = %s\n", tmp_str);
                        break;
                    
                    case NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX:
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

    //printf("Done handling response\n");
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

//  Note: this will fail if wifi radios are soft-disabled (e.g. with nmcli radio wifi off)
//  When this happens, the error code from nm80211 is -132
//TODO: use netlink to turn the wifi radio switch first
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

int get_wiphy(struct wifi_interface* wi) {
    struct nlmsghdr* nlh = mnl_nlmsg_put_header(nl_socket_buffer);
    struct genlmsghdr* genlh = (struct genlmsghdr*)mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
    unsigned int portid = mnl_socket_get_portid(nl_genl_socket);

    nlh->nlmsg_type = nl80211_family_id;
    nlh->nlmsg_pid = portid;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = seq;
    genlh->cmd = NL80211_CMD_GET_WIPHY;
    genlh->version = 2;
    mnl_attr_put_u32(nlh, NL80211_ATTR_IFINDEX, wi->ifindex);

    //mnl_nlmsg_fprintf(stderr, nl_socket_buffer, nlh->nlmsg_len, sizeof(struct genlmsghdr));

    if (mnl_socket_sendto(nl_genl_socket, nlh, nlh->nlmsg_len) < 0) {
        fprintf(stderr, "mnl_socket_sendto failed");
        return -1;
    }

    waiting_for_nl80211_phy = true;
    handle_response(nl_genl_socket);

    wi->wiphy = tmp_wiphy;
    memset(wi->wiphy_name, 0, MAX_WIPHY_NAME_LEN);
    strncpy(wi->wiphy_name, tmp_wiphy_name, MAX_WIPHY_NAME_LEN);

    return 0;
}

int get_interface(struct wifi_interface* wi) {
    struct nlmsghdr* nlh = mnl_nlmsg_put_header(nl_socket_buffer);
    struct genlmsghdr* genlh = (struct genlmsghdr*)mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
    unsigned int portid = mnl_socket_get_portid(nl_genl_socket);

    nlh->nlmsg_type = nl80211_family_id;
    nlh->nlmsg_pid = portid;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = seq;
    genlh->cmd = NL80211_CMD_GET_INTERFACE;
    genlh->version = 2;
    mnl_attr_put_u32(nlh, NL80211_ATTR_IFINDEX, wi->ifindex);

    //mnl_nlmsg_fprintf(stderr, nl_socket_buffer, nlh->nlmsg_len, sizeof(struct genlmsghdr));

    if (mnl_socket_sendto(nl_genl_socket, nlh, nlh->nlmsg_len) < 0) {
        fprintf(stderr, "mnl_socket_sendto failed");
        return -1;
    }

    waiting_for_nl80211_interface = true;
    handle_response(nl_genl_socket);

    /*wi->wiphy = tmp_wiphy;
    memset(wi->wiphy_name, 0, MAX_WIPHY_NAME_LEN);
    strncpy(wi->wiphy_name, tmp_wiphy_name, MAX_WIPHY_NAME_LEN);*/

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

    //mnl_nlmsg_fprintf(stderr, nl_socket_buffer, nlh->nlmsg_len, sizeof(struct genlmsghdr));

    if (mnl_socket_sendto(nl_genl_socket, nlh, nlh->nlmsg_len) < 0) {
        fprintf(stderr, "mnl_socket_sendto failed");
        return -1;
    }

    handle_response(nl_genl_socket);

    return 0;
}

int set_channel(const int ifindex, const uint32_t freq) {
    struct nlmsghdr* nlh = mnl_nlmsg_put_header(nl_socket_buffer);
    struct genlmsghdr* genlh = (struct genlmsghdr*)mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
    unsigned int portid = mnl_socket_get_portid(nl_genl_socket);

    nlh->nlmsg_type = nl80211_family_id;
    nlh->nlmsg_pid = portid;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = seq;
    genlh->cmd = NL80211_CMD_SET_CHANNEL;
    genlh->version = 2;
    mnl_attr_put_u32(nlh, NL80211_ATTR_IFINDEX, ifindex);
    mnl_attr_put_u32(nlh, NL80211_ATTR_WIPHY_FREQ, freq);
    mnl_attr_put_u32(nlh, NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_CHAN_NO_HT);

    mnl_nlmsg_fprintf(stderr, nl_socket_buffer, nlh->nlmsg_len, sizeof(struct genlmsghdr));

    if (mnl_socket_sendto(nl_genl_socket, nlh, nlh->nlmsg_len) < 0) {
        fprintf(stderr, "mnl_socket_sendto failed");
        return -1;
    }

    handle_response(nl_genl_socket);

    return 0;
}

void update_table(hash_table_t *ht, const uint8_t *k, const time_t t) {
    int index = ht_search(ht, k);
    if (index == -1) {
        ht_insert2(ht, k, t);
    } else {
        ht->elements[index]->t = t;
    }
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

    struct pcap_pkthdr* pcap_hdr;
    const uint8_t* data;

    //TODO: handle case where pcap_next blocks until a 1st packet is received
    time_t now;
    while (!quit) {
        //  Wait for a packet from libpcap
        pcap_next_ex(p, &pcap_hdr, &data);

        wi->packet_count++;

        /* Note from the man page for pcap_next_ex:
           The struct pcap_pkthdr and the packet data are not to be freed by
           the caller, and are not guaranteed to be valid after the next call
           to pcap_next_ex(), pcap_next(), pcap_loop(3PCAP), or
           pcap_dispatch(3PCAP); if the code needs them to remain valid, it
           must make a copy of them.
           See: https://www.tcpdump.org/manpages/pcap_next_ex.3pcap.html */

        //  Look for radiotap header
        size_t rt_len = 0;
        if (pcap_hdr->len > RT_HDR_SIZE) {
            const struct ieee80211_radiotap_header* rth = (const struct ieee80211_radiotap_header*)data;
        
            //  As of April 2020, version is always zero
            //  see: https://www.radiotap.org/
            if(rth->it_version == 0 && rth->it_pad == 0) {
                //  This packet might have a radiotap header that must be skipped
                //  for hashing
                rt_len = rth->it_len;
            }
        }

        //  There's a weird bug where somehow rt_len ends up being the same
        //  as pcap_hdr->len, which causes an integer overflow below.
        //TODO: Diagnose the weird bug
        if (rt_len == pcap_hdr->len) {
            rt_len = 0;
        }

        //  If the last 4 bytes match an FCS over the frame, not counting the 
        //  radiotap header and last 4 bytes, the frame has an FCS present (and we
        //  need to ignore it when hashing)
        size_t fcs_len = 0;
        const uint32_t fcs = calc_crc(data + rt_len, pcap_hdr->len - rt_len - 4);
        if (data[pcap_hdr->len - 4] == (uint8_t)(fcs >> 24) &&
            data[pcap_hdr->len - 3] == (uint8_t)(fcs >> 16) &&
            data[pcap_hdr->len - 2] == (uint8_t)(fcs >> 8) &&
            data[pcap_hdr->len - 1] == (uint8_t)(fcs)) {
            //  Found an FCS
            fcs_len = 4;
        }

        //  Generate a SHA-256 hash over the packet data, considering the offset
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(mdctx, data + rt_len, pcap_hdr->len - rt_len - fcs_len);
        unsigned char *digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
        unsigned int digest_len = 32;
        EVP_DigestFinal_ex(mdctx, digest, &digest_len);
        EVP_MD_CTX_free(mdctx);

        //TODO: compare packet hashes across capture threads to identify missing packets
        now = time(NULL);
        
        //  Update packets for this interface
        pthread_mutex_lock(&interface_packets_mutex[wi->ai]);
        update_table(interface_packets[wi->ai], digest, now);
        pthread_mutex_unlock(&interface_packets_mutex[wi->ai]);

        //  Update all packets
        pthread_mutex_lock(&all_packets_mutex);
        update_table(all_packets, digest, now);
        pthread_mutex_unlock(&all_packets_mutex);
    }

    pcap_close(p);

    printf("Stopping capture thread for %s\n", wi->ifname);

    return 0;
}

void* stat_fn(void*) {

    time_t now;
    int i, j;
    //unsigned long long observed;
    //unsigned long long total;
    while (!quit) {
        now = time(NULL);

        pthread_mutex_lock(&all_packets_mutex);

        //  Iterate the all-packets table
        for (i = 0; i < all_packets->size; ++i) {
            if (all_packets->elements[i] != NULL) {
                //  The strategy for finding missed packets is to iterate all
                //  observed packet hashes, checking whether each interface under
                //  test has seen it.  However, I think if I check the interface
                //  hash_tables too soon after first seeing the packet, there may
                //  be some possibility of mistakenly counting a packet as missed
                //  due to a timing coincidence.  To avoid this, I wait some time
                //  before doing the miss check.

                //  If this packet is less than 2 seconds old, skip it
                if (now - all_packets->elements[i]->t < 2) {
                    continue;
                }

                //  Search all interface tables for this packet
                for (j = 0; j < num_interfaces; ++j) {
                    pthread_mutex_lock(&interface_packets_mutex[j]);

                    if (-1 == ht_search(interface_packets[j], all_packets->elements[i]->k)) {
                        //  Interface j missed frame i
                        interfaces[j].frames_missed++;
                    }

                    pthread_mutex_unlock(&interface_packets_mutex[j]);
                    //printf("Count for interface %d = %llu\n", j, interfaces[j].packet_count);
                }

                ht_delete(all_packets, i);
            }
        }

        //printf("all packets table count: %d\n", all_packets->count);

        pthread_mutex_unlock(&all_packets_mutex);

        sleep(1);
    }

    printf("Stopping stat thread\n");

    return 0;
}

int main(int argc, char* argv[]) {
    int retval = EXIT_SUCCESS;
    pthread_t stat_thread_id;
    pthread_t thread_id[MAX_INTERFACES];
    bool log_mode = false;

    nl_socket_buffer = malloc(MNL_SOCKET_BUFFER_SIZE);
    if (nl_socket_buffer == NULL) {
        retval = EXIT_FAILURE;
        goto end;
    }

    signal(SIGINT, sighandler);

    //  Configure program options
    //TODO: add support for HT channels
    struct option long_opts[] = {
        { "channel", required_argument, 0, 'c' },
        { "interface", required_argument, 0, 'i' },
        { "log", no_argument, 0, 'l'},
        { 0, 0, 0, 0 }
    };

    const char* optstr = "c:i:l";
    uint32_t channel = 1;
    int opt;
    int ai = 0;
    while ((opt = getopt_long(argc, argv, optstr, long_opts, &optind)) != -1) {
        switch (opt) {
        case 'c': {
            char* end;
            channel = strtoul(optarg, &end, 10);
            if (valid_channel(channel)) {
                printf("Using channel %u\n", channel);
            } else {
                fprintf(stderr, "Invalid or unsupported channel: %s\n", optarg);
                retval = EXIT_FAILURE;
                goto cleanup_nl_socket_buffer;
            }
        }
        break;

        case 'i': {
            //  Check if the interface is real
            const int ifindex = if_nametoindex(optarg);
            if (ifindex > 0) {
                printf("Using interface %s\n", optarg);
                memset(&interfaces[ai], 0, sizeof(struct wifi_interface));
                strncpy(interfaces[ai].ifname, optarg, MAX_IF_NAME_LEN);
                interfaces[ai].ifindex = if_nametoindex(optarg);
                interfaces[ai].ai = ai;
                num_interfaces++;
                ai++;
            } else {
                fprintf(stderr, "Interface %s doesn't seem to exist\n", optarg);
                retval = EXIT_FAILURE;
                goto cleanup_nl_socket_buffer;
            }
        }
        break;

        case 'l':
            log_mode = true;
            printf("Using log mode - no curses UI will be displayed\n");
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
        goto end;
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

    //  Determine nl80211 genl family id.  Annoyingly, this isn't a fixed value.
    printf("Querying for nl80211 family id\n");
    if (get_nl80211_family_id() < 0) {
        fprintf(stderr, "get_nl80211_family_id failed\n");
        goto cleanup_nl_genl_socket;
    }

    all_packets = ht_alloc(1021);
    pthread_mutex_init(&all_packets_mutex, NULL);

    //  Start stat thread
    pthread_create(&stat_thread_id, NULL, stat_fn, (void *)NULL);

    //  Configure interfaces
    for (int i = 0; i < num_interfaces; i++) {
        printf("Configuring (%d)%s\n", interfaces[i].ifindex, interfaces[i].ifname);

        //  TODO: Remember initial interface mode and restore it when we're done
        printf("Getting info for %s\n", interfaces[i].ifname);
        get_wiphy(&interfaces[i]);
        get_interface(&interfaces[i]);

        //  Bring the interface down
        printf("Bringing down %s\n", interfaces[i].ifname);
        if_down(&interfaces[i]);

        //  Set monitor mode
        printf("Setting %s to monitor mode\n", interfaces[i].ifname);
        set_monitor_mode(&interfaces[i]);

        //  Bring the interface up
        printf("Bringing up %s\n", interfaces[i].ifname);
        if_up(&interfaces[i]);

        //  Set channel
        printf("Setting %s to channel %u\n", interfaces[i].ifname, channel);
        set_channel(interfaces[i].ifindex, channel_to_freq(channel));

        //  Initialize hash table and mutex
        interface_packets[i] = ht_alloc(1021);
        pthread_mutex_init(&interface_packets_mutex[i], NULL);

        //  Start capture thread
        pthread_create(&thread_id[i], NULL, packet_capture_fn, (void*)&interfaces[i]);
    }

    //  Set up ncurses
    if (!log_mode) {
        initscr();
        noecho();
        wininit();
    }

    //  Remember start time
    start_time = time(NULL);

    while (!quit) {
        if (!log_mode) {
            winupdate();

            //  This configures the timeout for ncurses getch()
            timeout(1000);

            //  Read input from the user - doubles as trigger for window resize
            //  notification via KEY_RESIZE
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
        } else {
            sleep(1);
        }
    }

    endwin();

    //  Join stat thread
    pthread_join(stat_thread_id, NULL);

    //  Join capture threads
    for (int i = 0; i < num_interfaces; ++i) {
        pthread_join(thread_id[i], NULL);
        ht_free(interface_packets[i]);
    }

    ht_free(all_packets);

cleanup_nl_genl_socket:
    mnl_socket_close(nl_genl_socket);
    nl_genl_socket = NULL;

cleanup_nl_route_socket:
    mnl_socket_close(nl_route_socket);
    nl_route_socket = NULL;

cleanup_nl_socket_buffer:
    free(nl_socket_buffer);
    nl_socket_buffer = NULL;

end:
    return retval;
}
