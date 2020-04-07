/**
 * Shootout2 - 802.11 monitor mode performance evaluator
 *
 * Copyright 2020 Ted DeLoggio <deltj@outlook.com>
 */
#include "Packet.h"

#define BOOST_TEST_MODULE PacketTest
#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include<vector>
#include<set>

static const uint8_t testHash1[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

static const uint8_t testHash2[32] = {
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55
};

BOOST_AUTO_TEST_CASE( PacketHash_Operators )
{
    shootout::PacketHash ph1(testHash1);
    shootout::PacketHash ph2(testHash2);
    shootout::PacketHash ph3(testHash1);

    BOOST_CHECK(ph1 != ph2);
    BOOST_CHECK(ph1 == ph3);
    BOOST_CHECK(ph1 < ph2);
    BOOST_CHECK(ph2 > ph1);
}

BOOST_AUTO_TEST_CASE( PacketHash_Vector )
{
    std::vector<shootout::PacketHash> phv;

    shootout::PacketHash ph1(testHash1);
    phv.push_back(ph1);

    BOOST_CHECK_EQUAL(1, phv.size());
}

BOOST_AUTO_TEST_CASE( PacketHash_Set )
{
    std::set<shootout::PacketHash> phs;

    shootout::PacketHash ph1(testHash1);
    shootout::PacketHash ph2(testHash2);

    phs.insert(ph1);
    phs.insert(ph2);

    BOOST_CHECK_EQUAL(2, phs.size());
}

BOOST_AUTO_TEST_CASE( Ctor )
{
    shootout::Packet p;

    BOOST_CHECK_EQUAL(0, p.dataLength);
    BOOST_CHECK_EQUAL(nullptr, p.data);
}

BOOST_AUTO_TEST_CASE( CopyCtor )
{
    uint8_t data[100];
    for(int i=0; i<100; i++)
        data[i] = 0x55;

    shootout::Packet p1;
    p1.setData(data, 100);

    shootout::Packet p2 = p1;

    uint8_t copiedPacketdata[100];
    const int numCopied = p2.getData(copiedPacketdata, 100);
    BOOST_CHECK_EQUAL(100, numCopied);

    for(int i=0; i<100; ++i)
        BOOST_CHECK_EQUAL(0x55, copiedPacketdata[i]);
}

BOOST_AUTO_TEST_CASE( GetSetData )
{
    uint8_t data[100];

    for(int i=0; i<100; ++i)
        data[i] = 0x55;

    shootout::Packet p;
    p.setData(data, 100);

    BOOST_CHECK_EQUAL(100, p.dataLength);
    BOOST_CHECK(p.data != nullptr);

    uint8_t copiedPacketdata[100];
    const int numCopied = p.getData(copiedPacketdata, 100);
    BOOST_CHECK_EQUAL(100, numCopied);

    for(int i=0; i<100; ++i)
        BOOST_CHECK_EQUAL(0x55, copiedPacketdata[i]);
}

BOOST_AUTO_TEST_CASE( GetEmptyPacket )
{
    shootout::Packet p;

    uint8_t buf[100];

    const bool numCopied = p.getData(buf, 100);

    BOOST_CHECK_EQUAL(0, numCopied);
}

BOOST_AUTO_TEST_CASE( GetNullBuff )
{
    uint8_t data[100];

    shootout::Packet p;
    p.setData(data, 100);

    uint8_t *buf = nullptr;

    const bool numCopied = p.getData(buf, 100);

    BOOST_CHECK_EQUAL(0, numCopied);
}

BOOST_AUTO_TEST_CASE( GetBuffTooSmall )
{
    uint8_t data[100];

    shootout::Packet p;
    p.setData(data, 100);

    uint8_t buf[99];

    const bool numCopied = p.getData(buf, 99);

    BOOST_CHECK_EQUAL(0, numCopied);
}

BOOST_AUTO_TEST_CASE( Hash )
{
    uint8_t data1[100];
    for(int i=0; i<100; i++)
        data1[i] = 0x55;

    uint8_t data2[100];
    for(int i=0; i<100; i++)
        data2[i] = 0xAA;

    shootout::Packet p1;
    p1.setData(data1, 100);

    shootout::Packet p2;
    p2.setData(data2, 100);

    shootout::Packet p3;
    p3.setData(data2, 100);

    uint8_t hash1[32];
    memcpy(hash1, p1.hash.hash, 32);

    uint8_t hash2[32];
    memcpy(hash2, p2.hash.hash, 32);

    uint8_t hash3[32];
    memcpy(hash3, p3.hash.hash, 32);

    int compare = memcmp(hash1, hash2, 32);

    BOOST_CHECK(compare != 0);

    compare = memcmp(hash2, hash3, 32);

    BOOST_CHECK(compare == 0);
}

BOOST_AUTO_TEST_CASE( Set )
{
    uint8_t data1[100];
    for(int i=0; i<100; i++)
        data1[i] = 0x55;

    uint8_t data2[100];
    for(int i=0; i<100; i++)
        data2[i] = 0xAA;

    shootout::Packet p1;
    p1.setData(data1, 100);

    shootout::Packet p2;
    p2.setData(data2, 100);

    shootout::Packet p3;
    p3.setData(data2, 100);

    shootout::PacketSet ps;
    ps.insert(p1);
    ps.insert(p2);
    ps.insert(p3);

    BOOST_CHECK_EQUAL(3, ps.size());
}

