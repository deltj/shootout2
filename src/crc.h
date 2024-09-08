/**
 * This file is part of shootout2 - 802.11 monitor mode performance evaluator
 *
 * Copyright 2024 Ted DeLoggio <deltj@outlook.com>
 */
#ifndef SHOOTOUT_CRC_H
#define SHOOTOUT_CRC_H

#include <stddef.h>
#include <stdint.h>

/**
 * Calculate the CCITT CRC32 frame check sequence (FCS) for an IEEE 802.11 
 * frame.
 *
 * @param buf The buffer to compute the FCS for
 * @param bufLen The length of buf
 * @returns the FCS
 */
uint32_t calcfcs(const uint8_t *const buf, const size_t buf_len);

#endif