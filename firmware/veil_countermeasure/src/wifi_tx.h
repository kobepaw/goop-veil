/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 goop-veil contributors
 *
 * wifi_tx.h — WiFi frame transmission API.
 */

#ifndef WIFI_TX_H
#define WIFI_TX_H

#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Send a validated 802.11 frame.
 *
 * The frame passes through channel validation, power limiter check,
 * and frame filter before transmission. Any failure results in the
 * frame being dropped and an audit log entry.
 *
 * @param frame  Raw 802.11 frame bytes (starting with Frame Control)
 * @param len    Frame length in bytes
 * @return ESP_OK on success, ESP_ERR_NOT_ALLOWED if safety check fails
 */
esp_err_t wifi_tx_send_frame(const uint8_t *frame, size_t len);

/**
 * @brief Set the operating WiFi channel.
 *
 * @param channel  Channel number (must be 1-11 for US regulatory domain)
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG if out of range
 */
esp_err_t wifi_tx_set_channel(uint8_t channel);

/**
 * @brief Get TX frame statistics.
 *
 * @param[out] sent      Number of frames successfully sent (may be NULL)
 * @param[out] rejected  Number of frames rejected by safety checks (may be NULL)
 */
void wifi_tx_get_stats(uint32_t *sent, uint32_t *rejected);

/**
 * @brief Reset TX frame statistics to zero.
 *
 * @return ESP_OK
 */
esp_err_t wifi_tx_reset_stats(void);

#ifdef __cplusplus
}
#endif

#endif /* WIFI_TX_H */
