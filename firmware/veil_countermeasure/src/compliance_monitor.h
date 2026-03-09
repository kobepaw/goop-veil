/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 goop-veil contributors
 *
 * compliance_monitor.h — ADC power measurement and GPIO kill switch API.
 */

#ifndef COMPLIANCE_MONITOR_H
#define COMPLIANCE_MONITOR_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the compliance monitoring subsystem.
 *
 * Configures ADC for RF power measurement and GPIO for kill switch.
 *
 * @return ESP_OK on success
 */
esp_err_t compliance_monitor_init(void);

/**
 * @brief Execute one compliance monitoring cycle.
 *
 * Reads ADC power, checks hardware kill switch, and asserts the
 * kill event bit if any violation is detected.
 *
 * @param evt_group  FreeRTOS event group handle
 * @param kill_bit   Event bit to set when kill switch is asserted
 */
void compliance_monitor_tick(EventGroupHandle_t evt_group, EventBits_t kill_bit);

/**
 * @brief Attempt to clear a software-latched kill switch.
 *
 * Only succeeds if hardware switch is inactive and current power
 * is within limits.
 *
 * @param evt_group  FreeRTOS event group handle
 * @param kill_bit   Event bit to clear
 * @return ESP_OK if cleared, ESP_ERR_NOT_ALLOWED if conditions not met
 */
esp_err_t compliance_monitor_clear_kill_switch(EventGroupHandle_t evt_group,
                                               EventBits_t kill_bit);

/**
 * @brief Get the last measured RF power.
 *
 * @return Power in dBm, or -99.0 if no measurement available
 */
float compliance_monitor_get_power_dbm(void);

/**
 * @brief Get compliance monitoring statistics.
 *
 * @param[out] total_samples    Total ADC samples taken (may be NULL)
 * @param[out] total_violations Total over-limit detections (may be NULL)
 * @param[out] kill_latched     Whether kill switch is currently latched (may be NULL)
 */
void compliance_monitor_get_stats(uint32_t *total_samples,
                                  uint32_t *total_violations,
                                  bool *kill_latched);

#ifdef __cplusplus
}
#endif

#endif /* COMPLIANCE_MONITOR_H */
