/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 goop-veil contributors
 *
 * legitimate_functions.h — Mesh AP, sensor, and FTM API.
 */

#ifndef LEGITIMATE_FUNCTIONS_H
#define LEGITIMATE_FUNCTIONS_H

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize legitimate functions (sensors, mesh, FTM).
 *
 * @return ESP_OK on success
 */
esp_err_t legitimate_functions_init(void);

/**
 * @brief Execute one tick of legitimate function processing.
 *
 * Reads sensors, manages mesh peers, and performs FTM ranging
 * according to their respective schedules.
 */
void legitimate_functions_tick(void);

/**
 * @brief Get the latest sensor readings.
 *
 * @param[out] temperature_c  Temperature in Celsius (may be NULL)
 * @param[out] humidity_pct   Relative humidity percentage (may be NULL)
 * @return ESP_OK if valid data available, ESP_ERR_NOT_FOUND otherwise
 */
esp_err_t legitimate_functions_get_sensor_data(float *temperature_c,
                                                float *humidity_pct);

/**
 * @brief Get the number of connected mesh peers.
 *
 * @return Number of associated mesh stations
 */
int legitimate_functions_get_mesh_peer_count(void);

#ifdef __cplusplus
}
#endif

#endif /* LEGITIMATE_FUNCTIONS_H */
