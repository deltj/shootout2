/**
 * This file is part of shootout2 - 802.11 monitor mode performance evaluator
 *
 * Copyright 2024 Ted DeLoggio <deltj@outlook.com>
 */
#include <stdio.h>
#include <stdlib.h>

#include <check.h>

#include "hash_table.h"

START_TEST(ht_alloc_test1) {
    hash_table_t * ht = NULL;

    ht = ht_alloc(1021);

    ck_assert_ptr_nonnull(ht);
    ck_assert_ptr_nonnull(ht->elements);
    ck_assert_uint_eq(ht->size, 1021);

    for (int i = 0; i < 1021; ++i) {
        ck_assert_ptr_null(ht->elements[i]);
    }

    ht_free(ht);
}

START_TEST(ht_alloc_test2) {
    hash_table_t * ht = NULL;

    ht = ht_alloc(5);

    ck_assert_ptr_nonnull(ht);
    ck_assert_ptr_nonnull(ht->elements);
    ck_assert_uint_eq(ht->size, 1021);

    for (int i = 0; i < 1021; ++i) {
        ck_assert_ptr_null(ht->elements[i]);
    }

    ht_free(ht);
}

START_TEST(ht_insert_test1) {
    hash_table_t * ht = NULL;

    ht = ht_alloc(1021);

    ck_assert_ptr_nonnull(ht);

    const uint8_t data[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    int idx1 = ht_insert(ht, data, 0);
    int idx2 = ht_insert(ht, data, 0);

    ck_assert_int_lt(idx1, 1021);
    ck_assert_int_lt(idx2, 1021);
    ck_assert_int_ne(idx1, idx2);

    ht_free(ht);
}

START_TEST(ht_insert_test2) {
    hash_table_t * ht = NULL;

    ht = ht_alloc(1021);

    ck_assert_ptr_nonnull(ht);

    const uint8_t data[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    //  Fill the table
    int idx = -1;
    for (int i = 0; i < 1021; ++i) {
        idx = ht_insert(ht, data, 0);
        ck_assert_int_ge(idx, 0);
    }

    ck_assert_int_eq(ht->count, 1021);

    //  The next call to ht_insert should return -1
    idx = ht_insert(ht, data, 0);
    ck_assert_int_eq(idx, -1);

    ht_free(ht);
}

START_TEST(ht_search_test) {
    hash_table_t * ht = NULL;

    ht = ht_alloc(1021);

    ck_assert_ptr_nonnull(ht);

    const uint8_t data[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    int idx1 = ht_insert(ht, data, 0);
    int idx2 = ht_search(ht, data);

    ck_assert_int_lt(idx1, 1021);
    ck_assert_int_lt(idx2, 1021);
    ck_assert_int_eq(idx1, idx2);

    ht_free(ht);
}

START_TEST(ht_delete_test1) {
    hash_table_t * ht = NULL;

    ht = ht_alloc(1021);

    ck_assert_ptr_nonnull(ht);

    const uint8_t data[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    int idx1 = ht_insert(ht, data, 0);
    int idx2 = ht_search(ht, data);

    ck_assert_int_lt(idx1, 1021);
    ck_assert_int_lt(idx2, 1021);
    ck_assert_int_eq(idx1, idx2);

    ht_delete(ht, idx2);
    ck_assert_ptr_null(ht->elements[idx2]);

    int idx3 = ht_search(ht, data);

    ck_assert_int_eq(idx3, -1);

    ht_free(ht);
}

START_TEST(ht_delete_test2) {
    hash_table_t * ht = NULL;

    ht = ht_alloc(1021);

    ck_assert_ptr_nonnull(ht);

    const uint8_t data[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    int idx1 = ht_insert(ht, data, 0);
    int idx2 = ht_insert(ht, data, 0);
    int idx3 = ht_search(ht, data);

    ck_assert_int_lt(idx1, 1021);
    ck_assert_int_lt(idx2, 1021);
    ck_assert_int_eq(idx1, idx3);

    //  The element at idx2 should be shifted down to idx1
    ht_delete(ht, idx1);
    ck_assert_ptr_nonnull(ht->elements[idx1]);
    ck_assert_ptr_null(ht->elements[idx2]);

    int idx4 = ht_search(ht, data);
    ck_assert_int_eq(idx4, idx1);

    ht_free(ht);
}

Suite *suite(void) {
    Suite *s;
    TCase *tc_ht_alloc_test1;
    TCase *tc_ht_alloc_test2;
    TCase *tc_ht_insert_test1;
    TCase *tc_ht_insert_test2;
    TCase *tc_ht_search_test;
    TCase *tc_ht_delete_test1;
    TCase *tc_ht_delete_test2;

    s = suite_create("hash_table");

    tc_ht_alloc_test1 = tcase_create("ht_alloc_test1");
    tc_ht_alloc_test2 = tcase_create("ht_alloc_test2");
    tc_ht_insert_test1 = tcase_create("ht_insert_test1");
    tc_ht_insert_test2 = tcase_create("ht_insert_test2");
    tc_ht_search_test = tcase_create("ht_search_test");
    tc_ht_delete_test1 = tcase_create("ht_delete_test1");
    tc_ht_delete_test2 = tcase_create("ht_delete_test2");

    tcase_add_test(tc_ht_alloc_test1, ht_alloc_test1);
    tcase_add_test(tc_ht_alloc_test2, ht_alloc_test2);
    tcase_add_test(tc_ht_insert_test1, ht_insert_test1);
    tcase_add_test(tc_ht_insert_test2, ht_insert_test2);
    tcase_add_test(tc_ht_search_test, ht_search_test);
    tcase_add_test(tc_ht_delete_test1, ht_delete_test1);
    tcase_add_test(tc_ht_delete_test2, ht_delete_test2);

    suite_add_tcase(s, tc_ht_alloc_test1);
    suite_add_tcase(s, tc_ht_alloc_test2);
    suite_add_tcase(s, tc_ht_insert_test1);
    suite_add_tcase(s, tc_ht_insert_test2);
    suite_add_tcase(s, tc_ht_search_test);
    suite_add_tcase(s, tc_ht_delete_test1);
    suite_add_tcase(s, tc_ht_delete_test2);

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