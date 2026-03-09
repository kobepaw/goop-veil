/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 goop-veil contributors
 *
 * power_limiter.h — TX power limiting API.
 */

#ifndef POWER_LIMITER_H
#define POWER_LIMITER_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the power limiter and set initial TX power.
 *
 * Sets TX power to MAX_TX_POWER_DBM and verifies the setting.
 *
 * @return ESP_OK on success
 */
esp_err_t power_limiter_init(void);

/**
 * @brief Check that current TX power is within limits.
 *
 * If power exceeds the limit, attempts to auto-correct. Returns false
 * (fail closed) if power cannot be verified or corrected.
 *
 * @return true if power is within limits, false otherwise
 */
bool power_limiter_check(void);

/**
 * @brief Set TX power to a specified level.
 *
 * The value is clamped to MAX_TX_POWER_DBM if it exceeds the limit.
 *
 * @param power_dbm  Desired power in dBm
 * @return ESP_OK on success
 */
esp_err_t power_limiter_set_power(int8_t power_dbm);

/**
 * @brief Get the current TX power setting.
 *
 * @return Current power in dBm
 */
float power_limiter_get_current_dbm(void);

#ifdef __cplusplus
}
#endif

#endif /* POWER_LIMITER_H */
