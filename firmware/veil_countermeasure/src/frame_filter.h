/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 goop-veil contributors
 *
 * frame_filter.h — SAFETY CRITICAL: Frame type and destination filter API.
 */

#ifndef FRAME_FILTER_H
#define FRAME_FILTER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Frame filter validation result codes.
 */
typedef enum {
    FRAME_FILTER_PASS            = 0,   /**< Frame is safe to transmit */
    FRAME_FILTER_INVALID_LENGTH  = -1,  /**< Frame too short or NULL */
    FRAME_FILTER_BROADCAST_DEAUTH = -2, /**< Broadcast/multicast deauth/disassoc */
    FRAME_FILTER_FOREIGN_BSSID   = -3,  /**< BSSID does not match own BSS */
    FRAME_FILTER_NOT_OWN_BSS     = -4,  /**< Destination not in own BSS table */
    FRAME_FILTER_NOT_INITIALIZED = -5,  /**< Filter not initialized */
    FRAME_FILTER_NO_BSSID        = -6,  /**< Own BSSID not yet known */
} frame_filter_result_t;

/**
 * @brief Initialize the frame filter subsystem.
 *
 * Must be called before any frame validation. Creates the association
 * table mutex and retrieves the device's own BSSID.
 *
 * @return ESP_OK on success
 */
esp_err_t frame_filter_init(void);

/**
 * @brief Validate a frame against all safety rules.
 *
 * This is the authoritative safety gate. A frame MUST pass this check
 * before being submitted to esp_wifi_80211_tx().
 *
 * @param frame  Raw 802.11 frame bytes
 * @param len    Frame length
 * @return FRAME_FILTER_PASS if safe, negative error code otherwise
 */
frame_filter_result_t frame_filter_validate(const uint8_t *frame, size_t len);

/**
 * @brief Add a station to the own-BSS association table.
 *
 * Only stations in this table may receive deauth/disassoc frames.
 *
 * @param mac  6-byte MAC address
 * @return ESP_OK on success, ESP_ERR_NO_MEM if table is full
 */
esp_err_t frame_filter_add_station(const uint8_t *mac);

/**
 * @brief Remove a station from the own-BSS association table.
 *
 * @param mac  6-byte MAC address
 * @return ESP_OK on success, ESP_ERR_NOT_FOUND if not in table
 */
esp_err_t frame_filter_remove_station(const uint8_t *mac);

/**
 * @brief Get the number of stations in the own-BSS association table.
 *
 * @return Station count, or -1 if mutex cannot be acquired
 */
int frame_filter_get_station_count(void);

#ifdef __cplusplus
}
#endif

#endif /* FRAME_FILTER_H */
