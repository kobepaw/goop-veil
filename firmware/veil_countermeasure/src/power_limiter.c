/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 goop-veil contributors
 *
 * power_limiter.c — TX power limiting and enforcement.
 *
 * Ensures that the ESP32-S3 WiFi transmit power never exceeds the
 * configured maximum (MAX_TX_POWER_DBM, default 20 dBm). The hardware
 * PA has an independent cutoff at HARDWARE_PA_CUTOFF_DBM (21 dBm).
 *
 * SAFETY INVARIANTS:
 *   - Software limit: MAX_TX_POWER_DBM (20 dBm conducted)
 *   - Hardware limit: PA cutoff at 21 dBm (independent of software)
 *   - Power is set at init and re-verified before each TX burst
 *   - Power NEVER adapts in response to detected sensing
 *   - All power changes are audit-logged
 */

#include <string.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_err.h"

#include "power_limiter.h"
#include "audit_log.h"

static const char *TAG = "power_limit";

/* ESP-IDF wifi power is in 0.25 dBm units */
#define DBM_TO_WIFI_POWER(dbm)   ((int8_t)((dbm) * 4))
#define WIFI_POWER_TO_DBM(p)     ((float)(p) / 4.0f)

/* Maximum allowed power in ESP-IDF units */
#define MAX_WIFI_POWER   DBM_TO_WIFI_POWER(MAX_TX_POWER_DBM)

static bool s_initialized = false;
static int8_t s_current_power = 0;

/* ---------------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------------- */

esp_err_t power_limiter_init(void)
{
    if (s_initialized) {
        return ESP_OK;
    }

    /* Set TX power to maximum allowed limit */
    int8_t target_power = MAX_WIFI_POWER;

    esp_err_t ret = esp_wifi_set_max_tx_power(target_power);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set TX power: %s", esp_err_to_name(ret));
        return ret;
    }

    /* Verify the power was actually set (ESP-IDF may clamp it) */
    int8_t actual_power = 0;
    ret = esp_wifi_get_max_tx_power(&actual_power);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read back TX power: %s", esp_err_to_name(ret));
        return ret;
    }

    if (actual_power > MAX_WIFI_POWER) {
        /* This should never happen, but if it does, force it down */
        ESP_LOGE(TAG, "TX power readback (%.2f dBm) exceeds limit (%d dBm) — "
                 "forcing to limit", WIFI_POWER_TO_DBM(actual_power),
                 MAX_TX_POWER_DBM);
        ret = esp_wifi_set_max_tx_power(MAX_WIFI_POWER);
        if (ret != ESP_OK) {
            return ret;
        }
        actual_power = MAX_WIFI_POWER;
    }

    s_current_power = actual_power;
    s_initialized = true;

    ESP_LOGI(TAG, "TX power limiter initialized: %.2f dBm (max: %d dBm, "
             "HW cutoff: %d dBm)",
             WIFI_POWER_TO_DBM(s_current_power),
             MAX_TX_POWER_DBM, HARDWARE_PA_CUTOFF_DBM);

    return ESP_OK;
}

bool power_limiter_check(void)
{
    if (!s_initialized) {
        ESP_LOGE(TAG, "Power limiter not initialized — failing closed");
        return false;
    }

    int8_t current = 0;
    esp_err_t ret = esp_wifi_get_max_tx_power(&current);
    if (ret != ESP_OK) {
        /* Cannot read power — fail closed */
        ESP_LOGE(TAG, "Cannot read TX power — failing closed");
        return false;
    }

    if (current > MAX_WIFI_POWER) {
        ESP_LOGE(TAG, "TX power (%.2f dBm) exceeds limit (%d dBm) — "
                 "attempting to reduce",
                 WIFI_POWER_TO_DBM(current), MAX_TX_POWER_DBM);

        /* Attempt to force power back to limit */
        ret = esp_wifi_set_max_tx_power(MAX_WIFI_POWER);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "CRITICAL: Cannot reduce TX power — halting TX");
            audit_log_record("POWER_VIOLATION", "cannot_reduce",
                             (int)WIFI_POWER_TO_DBM(current), NULL, 0);
            return false;
        }

        audit_log_record("POWER_VIOLATION", "auto_corrected",
                         (int)WIFI_POWER_TO_DBM(current), NULL, 0);
        ESP_LOGW(TAG, "TX power auto-corrected to %d dBm", MAX_TX_POWER_DBM);
    }

    s_current_power = current;
    return true;
}

esp_err_t power_limiter_set_power(int8_t power_dbm)
{
    if (!s_initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    /* Enforce ceiling */
    if (power_dbm > MAX_TX_POWER_DBM) {
        ESP_LOGW(TAG, "Requested power %d dBm exceeds limit %d dBm — clamping",
                 power_dbm, MAX_TX_POWER_DBM);
        power_dbm = MAX_TX_POWER_DBM;
    }

    /* Enforce floor (ESP32-S3 minimum is ~2 dBm) */
    if (power_dbm < 2) {
        power_dbm = 2;
    }

    int8_t wifi_power = DBM_TO_WIFI_POWER(power_dbm);
    esp_err_t ret = esp_wifi_set_max_tx_power(wifi_power);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set TX power to %d dBm: %s",
                 power_dbm, esp_err_to_name(ret));
        return ret;
    }

    /* Verify */
    int8_t actual = 0;
    esp_wifi_get_max_tx_power(&actual);
    s_current_power = actual;

    ESP_LOGI(TAG, "TX power set to %.2f dBm (requested: %d dBm)",
             WIFI_POWER_TO_DBM(actual), power_dbm);
    audit_log_record("POWER_SET", "ok", power_dbm, NULL, 0);

    return ESP_OK;
}

float power_limiter_get_current_dbm(void)
{
    return WIFI_POWER_TO_DBM(s_current_power);
}
