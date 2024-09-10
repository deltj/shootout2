/**
 * This file is part of shootout2 - 802.11 monitor mode performance evaluator
 *
 * Copyright 2024 Ted DeLoggio <deltj@outlook.com>
 */
#ifndef SHOOTOUT_HASH_TABLE_H
#define SHOOTOUT_HASH_TABLE_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define KEY_SIZE 32

/* Each entry in the hash table includes a frame FCS (the key) and the time at
   which the frame was last observed */
typedef struct ht_element {
    uint8_t k[KEY_SIZE];
    time_t t;
} ht_element_t;

/* Hash table structure */
typedef struct hash_table {
    ht_element_t **elements;
    int size;
    int count;
} hash_table_t;

/* Allocate a new hash table with specified size.  Actual size allocated may
   be larger than requested. */
hash_table_t * ht_alloc(const int size);

/* Free the specified hash table */
void ht_free(hash_table_t *ht);

/* Insert a new element into the hash table */
int ht_insert(hash_table_t *ht, const uint8_t *k, const time_t t);

/* Search the hash table for an element with key k */
int ht_search(hash_table_t *ht, const uint8_t *k);

/* Delete an element from the hash table at index q */
void ht_delete(hash_table_t *ht, int q);

#endif