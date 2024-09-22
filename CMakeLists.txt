cmake_minimum_required(VERSION 3.0.0)

project(shootout2)

enable_testing()

set(CMAKE_C_FLAGS "-std=gnu11 -Wall -Wextra -g")

include_directories(${CMAKE_SOURCE_DIR}/src)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
pkg_check_modules(NL3 REQUIRED libnl-3.0)
pkg_check_modules(MNL REQUIRED libmnl)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(NCURSES REQUIRED ncurses)
pkg_check_modules(CHECK REQUIRED check)

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

add_library(libshootout
    src/crc.c
    src/wifi.c
    src/hash_table.c
    )
set_target_properties(libshootout PROPERTIES PREFIX "")

add_executable(shootout
    src/shootout2.c
    )

target_include_directories(shootout PUBLIC
    ${GLIB2_INCLUDE_DIRS}
    ${NL3_INCLUDE_DIRS}
    ${MNL_INCLUDE_DIRS}
    ${KERNELHEADERS_DIR})

target_link_libraries(shootout
    pthread
    ${GLIB2_LIBRARIES}
    ${PCAP_LIBRARIES}
    ${NL3_LIBRARIES}
    ${MNL_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${NCURSES_LIBRARIES}
    libshootout
    )

#install(TARGETS shootout)

add_subdirectory(test)
