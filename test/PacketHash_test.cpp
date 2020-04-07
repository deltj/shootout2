/**
 * @file PacketHash_test.cpp
 *
 * Unit tests to prove that PacketHash works and can do the various things
 * I need it to do.
 */
#include "Packet.h"

#define BOOST_TEST_MODULE PacketHashTest
#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include<vector>
#include<set>

static const uint8_t testHash1[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

static const uint8_t testHash2[] = {
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55
};

BOOST_AUTO_TEST_CASE( PacketHash_Ctor )
{
    shootout::PacketHash ph;

    BOOST_CHECK(memcmp(shootout::emptyHash, ph.hash, shootout::HASH_SIZE) == 0);
}

BOOST_AUTO_TEST_CASE( PacketHash_CopyCtor )
{
    shootout::PacketHash ph(testHash2);

    BOOST_CHECK(memcmp(testHash2, ph.hash, shootout::HASH_SIZE) == 0);
}

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

    shootout::PacketHash ph2 = phv[0];

    BOOST_CHECK(memcmp(testHash1, ph2.hash, shootout::HASH_SIZE) == 0);
}

BOOST_AUTO_TEST_CASE( PacketHash_Set )
{
    std::set<shootout::PacketHash> phs;

    shootout::PacketHash ph1(testHash1);
    shootout::PacketHash ph2(testHash2);

    phs.insert(ph1);
    phs.insert(ph2);

    BOOST_CHECK_EQUAL(2, phs.size());

    shootout::PacketHash ph3(testHash1);

    std::set<shootout::PacketHash>::const_iterator cit = phs.find(ph3);

    BOOST_CHECK(cit != phs.end());
    BOOST_CHECK(memcmp(testHash1, cit->hash, shootout::HASH_SIZE) == 0);
}

