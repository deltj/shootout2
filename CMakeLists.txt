cmake_minimum_required(VERSION 3.0.0)

project(shootout2)

enable_testing()

set(CMAKE_CXX_FLAGS "-std=c++17 -Wall -g -fprofile-arcs -ftest-coverage")
#-g -fprofile-arcs -ftest-coverage

include_directories(${CMAKE_SOURCE_DIR}/src)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
pkg_check_modules(NL3 REQUIRED libnl-3.0)
pkg_check_modules(GENL3 REQUIRED libnl-genl-3.0)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(NCURSES REQUIRED ncurses)

execute_process(
    COMMAND uname -r
    OUTPUT_VARIABLE KERNEL_RELEASE
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
message("Kernel release is ${KERNEL_RELEASE}")

find_path(
    KERNELHEADERS_DIR
    linux/nl80211.h
    PATHS /usr/src/linux-headers-${KERNEL_RELEASE} /usr/include
)
message("Found kernel headers in ${KERNELHEADERS_DIR}")

add_executable(shootout2
    src/shootout2.cpp
    src/Packet.cpp)

target_include_directories(shootout2 PUBLIC
    ${NL3_INCLUDE_DIRS}
    ${KERNELHEADERS_DIR})

target_link_libraries(shootout2
    pthread
    ${PCAP_LIBRARIES}
    ${NL3_LIBRARIES}
    ${GENL3_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${NCURSES_LIBRARIES}
    )

#install(TARGETS shootout2)

add_subdirectory(test)
