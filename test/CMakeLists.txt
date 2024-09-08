
add_executable(crc_test
    crc_test.c)
target_link_libraries(crc_test
    ${CHECK_LIBRARIES}
    libshootout
    )
add_test(crc_test crc_test)
