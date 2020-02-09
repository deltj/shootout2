cmake_minimum_required(VERSION 3.0.0)

project(shootout-ng)

set(CMAKE_CXX_FLAGS "-Wall -g")

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

add_executable(shootout-ng
    shootout-ng.cpp)

target_link_libraries(shootout-ng
    ${PCAP_LIBRARIES}
    )

install(TARGETS shootout-ng)
