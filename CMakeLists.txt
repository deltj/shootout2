cmake_minimum_required(VERSION 3.0.0)

project(shootout2)

enable_testing()

set(CMAKE_CXX_FLAGS "-std=c++17 -Wall -g -fprofile-arcs -ftest-coverage")
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

add_subdirectory(test)
