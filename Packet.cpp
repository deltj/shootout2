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
        data = std::make_unique<char[]>(dataLength);
        std::copy(src.data.get(), src.data.get() + dataLength, data.get());
    }
}

Packet::~Packet()
{
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
            data = std::make_unique<char[]>(dataLength);
            std::copy(src.data.get(), src.data.get() + dataLength, data.get());
        }
    }

    return *this;
}

int Packet::getData(uint8_t *const buf, const int &bufLen)
{
    if(buf == nullptr)
    {
        return 0;
    }

    if(bufLen < dataLength)
    {
        return 0;
    }

    memcpy(buf, data.get(), dataLength);

    return dataLength;
}

bool Packet::setData(const uint8_t *const buf, const int &bufLen)
{
    if(buf == nullptr)
    {
        return false;
    }

    dataLength = bufLen;

    data = std::make_unique<char[]>(bufLen);

    memcpy(data.get(), buf, dataLength);

    return true;
}

void Packet::getHash(uint8_t hash[32]) const
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.get(), dataLength);
    SHA256_Final(hash, &sha256);
}


}

