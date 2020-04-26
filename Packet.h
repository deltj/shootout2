/**
 * Shootout2 - 802.11 monitor mode performance evaluator
 *
 * Copyright 2020 Ted DeLoggio <deltj@outlook.com>
 */
#ifndef PACKET_H
#define PACKET_H

#include <chrono>
#include <cstring>
#include <memory>
#include <string>

namespace shootout
{

static const size_t HASH_SIZE = 32;

static const uint8_t emptyHash[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/**
 * Radiotap header structure
 */
struct ieee80211_radiotap_header {
    u_int8_t        it_version;     /* set to 0 */
    u_int8_t        it_pad;
    u_int16_t       it_len;         /* entire length */
    u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));

static const size_t RT_HDR_SIZE = sizeof(ieee80211_radiotap_header);

/**
 * Calculate the CCITT CRC32 frame check sequence (FCS) for an IEEE 802.11 
 * frame.
 *
 * @param buf The buffer to compute the FCS for
 * @param bufLen The length of buf
 * @returns the FCS
 */
uint32_t calcfcs(const uint8_t *const buf, const size_t bufLen);

/**
 * This class wraps a 256-bit hash value for use with STL containers
 */
class PacketHash
{
public:
    PacketHash();
    PacketHash(const uint8_t h[HASH_SIZE]);

    std::string toString() const;

    bool operator==(const PacketHash &rhs) const;
    bool operator!=(const PacketHash &rhs) const;
    bool operator<(const PacketHash &rhs) const;
    bool operator>(const PacketHash &rhs) const;

    uint8_t hash[HASH_SIZE];
};

/**
 * This class represents a packet that has been received by an interface in 
 * monitor mode.
 *
 * Note that packet hashes will exclude a radiotap header if one is present.
 * This is to prevent identical packets received by different interfaces from
 * appearing different because their RSSI values differ.
 */
class Packet
{
public:
    //!  Default constructor
    Packet();

    //!  Copy constructor
    Packet(const Packet &src);

    //!  Constructor with packet data
    Packet(const uint8_t *buf, const size_t bufLen);

    //!  Move constructor
    Packet(Packet &&src) = delete;

    //!  Destructor
    virtual ~Packet();

    //!  Copy-assignment operator
    Packet& operator=(const Packet& src);

    /**
     * Copies this packet's data into the specified buffer
     *
     * @param buf The destination buffer
     * @param bufLen The maximum number of bytes the destination buffer can store
     * @returns The number of bytes copied
     */
    int getData(uint8_t *const buf, const size_t bufLen);

    /**
     * Copies data from the specified buffer to this packet's buffer.
     *
     * @param buf The source buffer
     * @param bufLen The number of bytes to copy
     * @returns true if the copy was successful, false otherwise
     */
    bool setData(const uint8_t *const buf, const size_t bufLen);

    //!  The time at which this packet was received
    std::chrono::system_clock::time_point timeOfReceipt;

    //!  The interface that received the packet
    int ifindex;

    //!  The length in bytes of the packet's contents
    size_t dataLength;

    //!  The contents of the packet
    uint8_t *data;

    //!  A SHA-256 hash of the packet's contents
    PacketHash hash;
};

struct PacketComparator
{
    bool operator()(const Packet &a, const Packet &b) const
    {
        return a.hash != b.hash;
    }
};

}

#endif
