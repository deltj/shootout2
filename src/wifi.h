/**
 * shootout2 - 802.11 monitor mode performance evaluator
 *
 * Copyright 2024 Ted DeLoggio <deltj@outlook.com>
 */
#ifndef SHOOTOUT2_WIFI_CRC32_H
#define SHOOTOUT2_WIFI_CRC32_H

#include <stdbool.h>
#include <stdint.h>

extern const char * attrnames[];

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