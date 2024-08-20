/**
 * shootout2 - 802.11 monitor mode performance evaluator
 *
 * Copyright 2024 Ted DeLoggio <deltj@outlook.com>
 */
#ifndef SHOOTOUT2_WIFI_CRC32_H
#define SHOOTOUT2_WIFI_CRC32_H

#include <stdbool.h>
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

/**
 * Check whether the specified channel is a valid 802.11 wifi channel
 * 
 * @returns true if valid
 */
bool valid_channel(const uint32_t channel);

/**
 * Convert a wifi channel number to a frequency.
 * 
 * @param channel The channel to convert
 * @returns the frequency, or zero if there was an error
 */
uint32_t channel_to_freq(const uint32_t channel);

#endif