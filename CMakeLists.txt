cmake_minimum_required(VERSION 3.0.0)

project(shootout2)

enable_testing()

set(CMAKE_CXX_FLAGS "-std=c++17 -Wall")
#-g -fprofile-arcs -ftest-coverage

include_directories(${CMAKE_SOURCE_DIR})

find_package(PkgConfig REQUIRED)
#pkg_check_modules(PCAP REQUIRED libpcap)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(NCURSES REQUIRED ncurses)

add_executable(shootout2
    shootout2.cpp
    Packet.cpp)

target_link_libraries(shootout2
    -lpcap
    pthread
    ${OPENSSL_LIBRARIES}
    ${NCURSES_LIBRARIES}
    )

#install(TARGETS shootout2)

add_executable(PacketHash_test
    Packet.cpp
    test/PacketHash_test.cpp)
target_link_libraries(PacketHash_test
    ${OPENSSL_LIBRARIES}
    boost_unit_test_framework)
add_test(PacketHash_test PacketHash_test)

add_executable(Packet_test
    Packet.cpp
    test/Packet_test.cpp)
target_link_libraries(Packet_test
    ${OPENSSL_LIBRARIES}
    boost_unit_test_framework)
add_test(Packet_test Packet_test)
