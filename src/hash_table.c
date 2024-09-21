/**
 * This file is part of shootout2 - 802.11 monitor mode performance evaluator
 *
 * Copyright 2024 Ted DeLoggio <deltj@outlook.com>
 */
#include "hash_table.h"
#include "crc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Prime numbers for suggested hash tables sizes with modular hashing 
   Copied from section Algorithms in C section 14.1, 1998, Sedgewick */
int table_sizes[] = {
    1021,
    2039,
    4093,
    8191,
    16381,
    32749,
    65521,
    131071,
    262139,
    524287,
    1048573,
    2097143,
    4194301,
    8388593,
    16777213,
    33554393,
    67108859,
    134217689,
    268435399,
    536870909,
    1073741789,
    2147483647,
};

#define NUM_TABLE_SIZES 22

/* Find a suggested table size greater than or equal to x, or -1 if the
   requested size is unsupported */
int get_alloc_size(const int x) {
    for (int i = 0; i < NUM_TABLE_SIZES; ++i) {
        if (table_sizes[i] >= x) {
            return table_sizes[i];
        }
    }

    return -1;
}

hash_table_t * ht_alloc(const int size) {
    const int alloc_size = get_alloc_size(size);

    hash_table_t *ht = NULL;
    ht = malloc(sizeof(hash_table_t));
    ht->elements = calloc(sizeof(ht_element_t), alloc_size);
    ht->size = get_alloc_size(alloc_size);
    ht->count = 0;

    for (int i = 0; i < ht->size; ++i) {
        ht->elements[i] = NULL;
    }

    return ht;
}

void ht_free(hash_table_t *ht) {
    if (ht != NULL) {
        free(ht->elements);
        free(ht);
    }
}

int h(hash_table_t *ht, const uint8_t *k, int i) {
    return (calc_crc(k, 32) + i) % ht->size;
}

int ht_insert(hash_table_t *ht, const uint8_t *k, const time_t t) {
    //  Open addressing insert from CLRS 11.4
    const int m = ht->size;
    int i = 0;
    do {
        int q = h(ht, k, i);
        if (ht->elements[q] == NULL) {
            ht->elements[q] = malloc(sizeof(ht_element_t));
            ht->elements[q]->t = t;
            memcpy(ht->elements[q]->k, k, 32);
            ht->count += 1;
            return q;
        } else {
            i += 1;
        }
    } while (i < m);
    
    return -1;
}

int ht_insert2(hash_table_t *ht, const uint8_t *k, const time_t t) {
    int q = h(ht, k, 0);
    if (ht->elements[q] != NULL && ht->count > (ht->size / 2)) {
        //  The preferred slot is taken and the table is more than 50% full
        ht_resize(ht, ht->size + 1);
    }

    return ht_insert(ht, k, t);
}

int ht_search(hash_table_t *ht, const uint8_t *k) {
    //  Open addressing search from CLRS 11.4
    const int m = ht->size;
    int i = 0;
    do {
        int q = h(ht, k, i);
        if (ht->elements[q] != NULL && memcmp(ht->elements[q], k, KEY_SIZE) == 0) {
            return q;
        } else {
            i += 1;
        }
    } while (i < m);

    return -1;
}

void ht_resize(hash_table_t *ht, const int size) {
    if (size <= ht->size) {
        return;
    }

    const int new_alloc_size = get_alloc_size(size);
    const int old_size = ht->size;
    const int old_count = ht->count;

    //  Make a temporary copy of the elements
    ht_element_t **tmp_elements = ht->elements;

    //  Reinitialize the hash table with the new size
    ht->elements = calloc(sizeof(ht_element_t), new_alloc_size);
    ht->size = new_alloc_size;
    ht->count = 0;
    for (int i = 0; i < ht->size; ++i) {
        ht->elements[i] = NULL;
    }

    //  Insert old elements into the new hash table
    for (int i = 0; i < old_size; ++i) {
        if (tmp_elements[i] != NULL) {
            ht_insert(ht, tmp_elements[i]->k, tmp_elements[i]->t);            
        }
    }

    free(tmp_elements);
}

void ht_delete(hash_table_t *ht, int q) {
    //  Adapted from linear probing hash delete from CLRS 11.5.1
    const int m = ht->size;
    
    //printf("q=%d\n", q);
    if (ht->elements[q] == NULL) {
        return;
    }

    ht_element_t *e = ht->elements[q];
    ht->elements[q] = NULL;

    //  If any slots beyond q share the same key, they need to be shifted down
    for (int i = 0; i < m; ++i) {
        int ii = q + i % m;
        int jj = (q + i + 1) % m;

        //printf("ii=%d\n", ii);
        //printf("jj=%d\n", jj);

        //  Check if the next element is populated and the key matches
        if (ht->elements[jj] != NULL && memcmp(e->k, ht->elements[jj]->k, KEY_SIZE) == 0) {
            //  Shift it to the previous slot
            //printf("moving %d to %d\n", jj, ii);
            ht->elements[ii] = ht->elements[jj];
            ht->elements[jj] = NULL;
        } else {
            //printf("done\n");
            break;
        }
    }

    free(e);
    e = NULL;
}
