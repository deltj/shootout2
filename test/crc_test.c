/**
 * This file is part of shootout2 - 802.11 monitor mode performance evaluator
 *
 * Copyright 2024 Ted DeLoggio <deltj@outlook.com>
 */
#include <stdio.h>
#include <stdlib.h>

#include <check.h>

#include "crc.h"

START_TEST(test1) {
    const uint8_t data[] = {0xAA, 0xBB, 0xCC, 0xDD};

    const uint32_t fcs = calc_crc(data, 4);

    const uint32_t expected_fcs = 0x55B401A7;

    ck_assert_int_eq(expected_fcs, fcs);
}

START_TEST(test2) {
    const char * data = "test";

    const uint32_t fcs = calc_crc((const uint8_t *)data, 4);

    const uint32_t expected_fcs = 0xD87F7E0C;

    ck_assert_int_eq(expected_fcs, fcs);
}

START_TEST(test3) {
    /* TODO: capture a frame from a card that doesn't do checksum offloading */
    static const unsigned char data[4] = {
        0x00, 0x00, 0x00, 0x00
    };

    const uint32_t fcs = calc_crc(data, 4);

    const uint32_t expected_fcs = 0x2144DF1C;

    ck_assert_int_eq(expected_fcs, fcs);
}

Suite *suite(void) {
    Suite *s;
    TCase *tc_test1;
    TCase *tc_test2;
    TCase *tc_test3;

    s = suite_create("crc");

    tc_test1 = tcase_create("test1");
    tc_test2 = tcase_create("test2");
    tc_test3 = tcase_create("test3");

    tcase_add_test(tc_test1, test1);
    tcase_add_test(tc_test2, test2);
    tcase_add_test(tc_test3, test3);

    suite_add_tcase(s, tc_test1);
    suite_add_tcase(s, tc_test2);
    suite_add_tcase(s, tc_test3);

    return s;
}

int main(void) {
    int num_failed;
    Suite *s;
    SRunner *sr;

    s = suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    num_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (num_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}