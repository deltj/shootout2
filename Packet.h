/**
 * Shootout2 - 802.11 monitor mode performance evaluator
 *
 * Copyright 2020 Ted DeLoggio <deltj@outlook.com>
 */
#ifndef PACKET_H
#define PACKET_H

#include <memory>
#include <chrono>

namespace shootout
{

class Packet
{
public:
    Packet();
    Packet(const Packet &src);
    Packet(Packet &&src);
    virtual ~Packet();

    Packet& operator=(const Packet& src);

    bool setData(const uint8_t *const buf, const int &bufLen);
    int getData(uint8_t *const buf, const int &bufLen);
    void getHash(uint8_t hash[64]) const;

    //! The time at which this packet was received
    std::chrono::system_clock::time_point timeOfReceipt;

    //! The interface that received the packet
    int ifindex;

    //! The length in bytes of the packet's contents
    int dataLength;

    //! The contents of the packet
    std::unique_ptr<char[]> data;
};

}
#endif
