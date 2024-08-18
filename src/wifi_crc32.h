/**
 * shootout2 - 802.11 monitor mode performance evaluator
 *
 * Copyright 2024 Ted DeLoggio <deltj@outlook.com>
 */
#ifndef SHOOTOUT2_WIFI_CRC32_H
#define SHOOTOUT2_WIFI_CRC32_H

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