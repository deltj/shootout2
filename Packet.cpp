/**
 * Shootout2 - 802.11 monitor mode performance evaluator
 *
 * Copyright 2020 Ted DeLoggio <deltj@outlook.com>
 */
#include "Packet.h"

#include <cstring>

extern "C" {
#include "openssl/sha.h"
}

namespace shootout
{

PacketHash::PacketHash() 
{
    memcpy(hash, emptyHash, 32);
}

PacketHash::PacketHash(const uint8_t h[32])
{
    memcpy(hash, h, 32);
}

bool PacketHash::operator==(const PacketHash &rhs) const
{
    return memcmp(hash, rhs.hash, 32) == 0;
}

bool PacketHash::operator!=(const PacketHash &rhs) const
{
    return !(*this == rhs);
}

bool PacketHash::operator<(const PacketHash &rhs) const
{
    return memcmp(hash, rhs.hash, 32) < 0;
}

bool PacketHash::operator>(const PacketHash &rhs) const
{
    return memcmp(hash, rhs.hash, 32) > 0;
}

Packet::Packet() :
    timeOfReceipt(std::chrono::system_clock::now()),
    ifindex(-1),
    dataLength(0),
    data(nullptr)
{
}

Packet::Packet(const Packet &src) :
    timeOfReceipt(src.timeOfReceipt),
    ifindex(src.ifindex),
    dataLength(src.dataLength)
{
    if(dataLength != 0 && src.data != nullptr)
    {
        data = new uint8_t[dataLength];
        memcpy(data, src.data, dataLength);
    }
}

Packet::~Packet()
{
    if(data == nullptr)
    {
        delete data;
        data = nullptr;
        dataLength = 0;
    }
}

Packet& Packet::operator=(const Packet& src)
{
    if(&src != this)
    {
        timeOfReceipt = src.timeOfReceipt;
        ifindex = src.ifindex;
        dataLength = src.dataLength;

        if(dataLength != 0 && src.data != nullptr)
        {
            data = new uint8_t[dataLength];
            memcpy(data, src.data, dataLength);
        }
    }

    return *this;
}

int Packet::getData(uint8_t *const buf, const size_t bufLen)
{
    if(buf == nullptr)
    {
        return 0;
    }

    if(bufLen < dataLength)
    {
        return 0;
    }

    if(data != nullptr)
    {
        memcpy(buf, data, dataLength);
    }

    return dataLength;
}

bool Packet::setData(const uint8_t *const buf, const size_t bufLen)
{
    if(buf == nullptr)
    {
        return false;
    }

    if(data != nullptr)
    {
        delete data;
    }

    dataLength = bufLen;

    data = new uint8_t[dataLength];
    memcpy(data, buf, dataLength);

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, dataLength);
    SHA256_Final(hash.hash, &sha256);

    return true;
}

}

