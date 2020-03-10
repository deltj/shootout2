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
    BOOST_CHECK_EQUAL(nullptr, p.data.get());
}

BOOST_AUTO_TEST_CASE( GetSetData )
{
    uint8_t fakePacketData[100];

    for(int i=0; i<100; ++i)
        fakePacketData[i] = 0x55;

    shootout::Packet p;
    p.setData(fakePacketData, 100);

    BOOST_CHECK_EQUAL(100, p.dataLength);
    BOOST_CHECK(p.data != nullptr);

    uint8_t copiedPacketdata[100];
    const int numCopied = p.getData(copiedPacketdata, 100);
    BOOST_CHECK_EQUAL(100, numCopied);

    for(int i=0; i<100; ++i)
        BOOST_CHECK_EQUAL(0x55, copiedPacketdata[i]);
}

BOOST_AUTO_TEST_CASE( CopyCtor )
{
    uint8_t fakePacketData[100];
    for(int i=0; i<100; i++)
        fakePacketData[i] = 0x55;

    shootout::Packet p1;
    p1.setData(fakePacketData, 100);

    shootout::Packet p2 = p1;

    uint8_t copiedPacketdata[100];
    const int numCopied = p2.getData(copiedPacketdata, 100);
    BOOST_CHECK_EQUAL(100, numCopied);

    for(int i=0; i<100; ++i)
        BOOST_CHECK_EQUAL(0x55, copiedPacketdata[i]);
}

BOOST_AUTO_TEST_CASE( Hash )
{
    uint8_t fakePacketData[100];
    for(int i=0; i<100; i++)
        fakePacketData[i] = 0x55;

    shootout::Packet p;
    p.setData(fakePacketData, 100);

    uint8_t hash[32];
    p.getHash(hash);
}


