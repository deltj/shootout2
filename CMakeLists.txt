cmake_minimum_required(VERSION 3.0.0)

project(shootout2)

enable_testing()

set(CMAKE_CXX_FLAGS "-std=c++17 -Wall -g")

include_directories(${CMAKE_SOURCE_DIR})

find_package(PkgConfig REQUIRED)
#pkg_check_modules(PCAP REQUIRED libpcap)
pkg_check_modules(OPENSSL REQUIRED openssl)

add_executable(shootout2
    shootout2.cpp
    Packet.cpp)

target_link_libraries(shootout2
    -lpcap
    ${OPENSSL_LIBRARIES}
    pthread
    )

#install(TARGETS shootout2)

add_executable(Packet_test
    Packet.cpp
    test/Packet_test.cpp)

target_link_libraries(Packet_test
    ${OPENSSL_LIBRARIES}
    boost_unit_test_framework)

add_test(Packet_test Packet_test)
