/**
 * Shootout2 - 802.11 monitor mode performance evaluator
 *
 * Copyright 2020 Ted DeLoggio <deltj@outlook.com>
 */
#include "Packet.h"

#define BOOST_TEST_MODULE PacketTest
#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

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
    p1.getHash(hash1);

    uint8_t hash2[32];
    p2.getHash(hash2);

    uint8_t hash3[32];
    p3.getHash(hash3);

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

