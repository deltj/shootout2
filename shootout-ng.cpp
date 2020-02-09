/**
 * Next-gen shootout
 *
 * -Ted
 */
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" {
#include <byteswap.h>
#include <pcap.h>
}

#define ETH_ALEN 6

using namespace std;

static const uint8_t u8aRadiotapHeader[] =
{
    0x00, //  Version
    0x00, //  Header pad?
    0x18, 0x00, // <-- number of bytes in our header (count the number of "0x"s)

    /**
    * The next field is a bitmap of which options we are including.
    * The full list of which field is which option is in ieee80211_radiotap.h,
    * but I've chosen to include:
    *   0x00 0x01: timestamp
    *   0x00 0x02: flags
    *   0x00 0x03: rate
    *   0x00 0x04: channel
    *   0x80 0x00: tx flags (seems silly to have this AND flags, but oh well)
    */
    0x0f, 0x80, 0x00, 0x00,

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp

    /**
    * This is the first set of flags, and we've set the bit corresponding to
    * IEEE80211_RADIOTAP_F_FCS, meaning we want the card to add a FCS at the end
    * of our buffer for us.
    */
    0x10,

    0x00, // <-- rate
    0x00, 0x00, //  Channel
    0x00, 0x00, //  Channel flags

    /**
    * This is the second set of flags, specifically related to transmissions. The
    * bit we've set is IEEE80211_RADIOTAP_F_TX_NOACK, which means the card won't
    * wait for an ACK for this frame, and that it won't retry if it doesn't get
    * one.
    */
    0x08, 0x00,
};

struct ieee80211_hdr_3addr
{
    uint16_t frame_ctl;
    uint16_t dur;
    unsigned char addr1[ETH_ALEN];
    unsigned char addr2[ETH_ALEN];
    unsigned char addr3[ETH_ALEN];
    uint16_t seq_ctl;
};

void hexdump(const uint8_t *buf, const int &buf_len)
{
    int offset = 0;

    while(offset < buf_len)
    {
        printf("%04X ", offset);
        const int row_max = min(buf_len, offset + 16);
        for(; offset < row_max; offset++)
        {
            printf("%02X ", *(buf + offset));
            if((offset + 1) % 8 == 0)
            {
                printf(" ");
            }
        }
        printf("\n");
    }
}

int make_beacon(uint8_t *buf, const int &buf_len,
        const uint8_t amac[ETH_ALEN], const uint8_t smac[ETH_ALEN])
{
    int offset = 0;

    memcpy(buf, u8aRadiotapHeader, sizeof(u8aRadiotapHeader));
    offset += sizeof(u8aRadiotapHeader);

    //  Set up a beacon header
    struct ieee80211_hdr_3addr hdr;
    hdr.frame_ctl = bswap_16(0x8000);
    hdr.dur = 0xffff;
    memcpy(hdr.addr1, smac, ETH_ALEN);
    memcpy(hdr.addr2, amac, ETH_ALEN);
    memcpy(hdr.addr3, amac, ETH_ALEN);
    hdr.seq_ctl = 0;

    //  Copy the beacon header to the destination buffer
    memcpy(buf + offset, &hdr, sizeof(ieee80211_hdr_3addr));
    offset += sizeof(ieee80211_hdr_3addr);

    uint64_t timestamp = 1;
    memcpy(buf + offset, &timestamp, 8);
    offset += 8;

    uint16_t beacon_interval = 0x0064;
    memcpy(buf + offset, &beacon_interval, 2);
    offset += 2;

    uint16_t caps = 0x0431;
    memcpy(buf + offset, &caps, 2);
    offset += 2;

    uint8_t ssid[] = { 0x00, 0x04, 't', 'e', 's', 't' };
    memcpy(buf + offset, ssid, sizeof(ssid));
    offset += sizeof(ssid);
    
    uint8_t rates[] = { 0x01, 0x08, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c };
    memcpy(buf + offset, rates, sizeof(rates));
    offset += sizeof(rates);

    offset += 4; //fcs

    return offset;
}

int main(int argc, char *argv[])
{
    uint8_t amac[ETH_ALEN] = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };
    uint8_t smac[ETH_ALEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    uint8_t pkt[1000];

    int len = make_beacon(pkt, 1000, amac, smac);
    printf("len = %d\n", len);

    hexdump(pkt, len);

    /*
    pcap_t *pd = pcap_open_dead(DLT_IEEE802_11_RADIO, 65535);
    pcap_dumper_t *pdumper = pcap_dump_open(pd, "fart.pcap");
    struct pcap_pkthdr ph;
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    ph.ts = tv;
    ph.caplen = len;
    ph.len = len;
    pcap_dump((u_char*)pdumper, &ph, pkt);
    pcap_close(pd);
    pcap_dump_close(pdumper);
    */

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_live("wlp7s0", 800, 1, 20, errbuf);
    if(p == NULL)
    {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    if(pcap_sendpacket(p, pkt, len) == 0)
    {
        pcap_perror(p, "pcap_sendpacket");
        pcap_close(p);
        return EXIT_FAILURE;
    }

    pcap_close(p);

    return EXIT_SUCCESS;
}
