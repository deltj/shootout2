
add_executable(PacketHash_test
    ../Packet.cpp
    PacketHash_test.cpp)
target_link_libraries(PacketHash_test
    ${OPENSSL_LIBRARIES}
    boost_unit_test_framework)
add_test(PacketHash_test PacketHash_test)

add_executable(Packet_test
    ../Packet.cpp
    Packet_test.cpp)
target_link_libraries(Packet_test
    ${OPENSSL_LIBRARIES}
    boost_unit_test_framework)
add_test(Packet_test Packet_test)
