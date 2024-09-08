/**
 * This file is part of shootout2 - 802.11 monitor mode performance evaluator
 *
 * Copyright 2024 Ted DeLoggio <deltj@outlook.com>
 */
#include <stdlib.h>

#include <check.h>

#include "crc.h"

START_TEST(test1) {
    //const char *data = "this is a test";
    const uint8_t data[] = {0xAA};

    //  The packet above has a 24 byte radiotap header and a 4-byte
    //  FCS at the end, so the actual data is 214 bytes
    const uint32_t fcs = calcfcs(data, 1);

    const uint32_t expected_fcs = 0x62322f00;

    ck_assert_int_eq(expected_fcs, fcs);
}

Suite *crc_suite(void) {
    Suite *s;
    TCase *tc_test1;

    s = suite_create("crc");
    tc_test1 = tcase_create("test1");

    tcase_add_test(tc_test1, test1);
    suite_add_tcase(s, tc_test1);

    return s;
}

int main(void) {
    int num_failed;
    Suite *s;
    SRunner *sr;

    s = crc_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    num_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (num_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}