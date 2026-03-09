/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 goop-veil contributors
 *
 * compliance_monitor.c — ADC-based TX power measurement and GPIO kill switch.
 *
 * Continuously samples conducted RF power via an ADC-connected power
 * detector (e.g., AD8317 log detector). If measured power exceeds the
 * regulatory limit (MAX_TX_POWER_DBM), the kill switch event is asserted
 * to immediately halt all transmission.
 *
 * Additionally monitors a hardware kill switch GPIO for manual override.
 *
 * SAFETY INVARIANTS:
 *   - ADC sampling at >= 200 Hz (5ms interval in main loop)
 *   - Kill switch is asserted if ANY of:
 *       a) Measured power > MAX_TX_POWER_DBM (20 dBm)
 *       b) ADC read error (fail closed)
 *       c) Hardware GPIO kill switch is active (pulled LOW)
 *   - Kill switch can only be cleared by explicit software command
 *     after power is verified to be within limits
 *   - Hardware PA cutoff at 21 dBm provides independent safety layer
 */

#include <string.h>
#include <math.h>
#include "esp_log.h"
#include "esp_err.h"
#include "esp_adc/adc_oneshot.h"
#include "esp_adc/adc_cali.h"
#include "esp_adc/adc_cali_scheme.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#include "compliance_monitor.h"
#include "audit_log.h"

static const char *TAG = "compliance";

/* ---------------------------------------------------------------------------
 * Hardware configuration
 * --------------------------------------------------------------------------- */

/* ADC channel connected to RF power detector output */
#define POWER_ADC_UNIT       ADC_UNIT_1
#define POWER_ADC_CHANNEL    ADC_CHANNEL_3   /* GPIO4 on ESP32-S3 */
#define POWER_ADC_ATTEN      ADC_ATTEN_DB_12 /* 0-3.3V range */
#define POWER_ADC_BITWIDTH   ADC_BITWIDTH_12

/* Hardware kill switch GPIO (active LOW) */
#define GPIO_HW_KILL_SWITCH  GPIO_NUM_5

/* Power detector calibration:
 * AD8317: Vout = slope * Pin_dBm + intercept
 * Typical: slope = -22 mV/dB, intercept = 2200 mV at 0 dBm
 * These must be calibrated per-board. */
#define POWER_DET_SLOPE_MV_PER_DB    (-22.0f)
#define POWER_DET_INTERCEPT_MV       (2200.0f)

/* Consecutive over-limit samples before triggering (debounce) */
#define OVER_LIMIT_THRESHOLD   (3)

/* Number of samples to average for smoothing */
#define SAMPLE_AVERAGE_COUNT   (4)

/* ---------------------------------------------------------------------------
 * State
 * --------------------------------------------------------------------------- */

static adc_oneshot_unit_handle_t s_adc_handle = NULL;
static adc_cali_handle_t s_adc_cali_handle = NULL;
static bool s_initialized = false;
static bool s_kill_switch_latched = false;
static uint32_t s_over_limit_count = 0;
static float s_last_power_dbm = -99.0f;
static uint32_t s_total_samples = 0;
static uint32_t s_total_violations = 0;

/* ---------------------------------------------------------------------------
 * Internal helpers
 * --------------------------------------------------------------------------- */

/**
 * @brief Convert ADC voltage (mV) to RF power (dBm) using detector
 *        calibration curve.
 *
 * @param voltage_mv  Measured voltage in millivolts
 * @return Estimated RF power in dBm
 */
static float voltage_to_dbm(int voltage_mv)
{
    /* Pin_dBm = (Vout_mV - intercept) / slope */
    return ((float)voltage_mv - POWER_DET_INTERCEPT_MV) /
           POWER_DET_SLOPE_MV_PER_DB;
}

/**
 * @brief Read and average multiple ADC samples.
 *
 * @param[out] voltage_mv  Averaged voltage in millivolts
 * @return ESP_OK on success, error if any read fails
 */
static esp_err_t read_averaged_voltage(int *voltage_mv)
{
    int sum = 0;

    for (int i = 0; i < SAMPLE_AVERAGE_COUNT; i++) {
        int raw = 0;
        esp_err_t ret = adc_oneshot_read(s_adc_handle, POWER_ADC_CHANNEL, &raw);
        if (ret != ESP_OK) {
            return ret;
        }

        int mv = 0;
        if (s_adc_cali_handle != NULL) {
            ret = adc_cali_raw_to_voltage(s_adc_cali_handle, raw, &mv);
            if (ret != ESP_OK) {
                return ret;
            }
        } else {
            /* Fallback: approximate conversion without calibration */
            mv = (raw * 3300) / 4095;
        }

        sum += mv;
    }

    *voltage_mv = sum / SAMPLE_AVERAGE_COUNT;
    return ESP_OK;
}

/* ---------------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------------- */

esp_err_t compliance_monitor_init(void)
{
    if (s_initialized) {
        return ESP_OK;
    }

    /* Initialize ADC oneshot driver */
    adc_oneshot_unit_init_cfg_t init_cfg = {
        .unit_id = POWER_ADC_UNIT,
    };
    esp_err_t ret = adc_oneshot_new_unit(&init_cfg, &s_adc_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to init ADC unit: %s", esp_err_to_name(ret));
        return ret;
    }

    /* Configure ADC channel */
    adc_oneshot_chan_cfg_t chan_cfg = {
        .atten = POWER_ADC_ATTEN,
        .bitwidth = POWER_ADC_BITWIDTH,
    };
    ret = adc_oneshot_config_channel(s_adc_handle, POWER_ADC_CHANNEL, &chan_cfg);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to configure ADC channel: %s", esp_err_to_name(ret));
        return ret;
    }

    /* Try to create calibration handle (may not be available on all chips) */
    adc_cali_line_fitting_config_t cali_cfg = {
        .unit_id = POWER_ADC_UNIT,
        .atten = POWER_ADC_ATTEN,
        .bitwidth = POWER_ADC_BITWIDTH,
    };
    ret = adc_cali_create_scheme_line_fitting(&cali_cfg, &s_adc_cali_handle);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "ADC calibration not available — using approximate conversion");
        s_adc_cali_handle = NULL;
    }

    /* Configure hardware kill switch GPIO */
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << GPIO_HW_KILL_SWITCH),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    ret = gpio_config(&io_conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to configure kill switch GPIO: %s",
                 esp_err_to_name(ret));
        return ret;
    }

    s_initialized = true;
    s_kill_switch_latched = false;
    s_over_limit_count = 0;

    ESP_LOGI(TAG, "Compliance monitor initialized. Max TX power: %d dBm, "
             "HW PA cutoff: %d dBm", MAX_TX_POWER_DBM, HARDWARE_PA_CUTOFF_DBM);

    return ESP_OK;
}

void compliance_monitor_tick(EventGroupHandle_t evt_group, EventBits_t kill_bit)
{
    if (!s_initialized) {
        /* Not initialized — assert kill switch (fail closed) */
        xEventGroupSetBits(evt_group, kill_bit);
        return;
    }

    s_total_samples++;

    /* Check 1: Hardware kill switch GPIO (active LOW) */
    if (gpio_get_level(GPIO_HW_KILL_SWITCH) == 0) {
        if (!s_kill_switch_latched) {
            ESP_LOGW(TAG, "Hardware kill switch ACTIVE — halting all TX");
            audit_log_record("KILL_SWITCH", "hardware", 0, NULL, 0);
            s_kill_switch_latched = true;
        }
        xEventGroupSetBits(evt_group, kill_bit);
        return;
    }

    /* Check 2: ADC power measurement */
    int voltage_mv = 0;
    esp_err_t ret = read_averaged_voltage(&voltage_mv);
    if (ret != ESP_OK) {
        /* ADC read error — fail CLOSED (assert kill switch) */
        ESP_LOGE(TAG, "ADC read failed: %s — asserting kill switch (fail closed)",
                 esp_err_to_name(ret));
        audit_log_record("KILL_SWITCH", "adc_error", ret, NULL, 0);
        s_kill_switch_latched = true;
        xEventGroupSetBits(evt_group, kill_bit);
        return;
    }

    float power_dbm = voltage_to_dbm(voltage_mv);
    s_last_power_dbm = power_dbm;

    if (power_dbm > (float)MAX_TX_POWER_DBM) {
        s_over_limit_count++;
        s_total_violations++;

        if (s_over_limit_count >= OVER_LIMIT_THRESHOLD) {
            ESP_LOGE(TAG, "TX power OVER LIMIT: %.1f dBm > %d dBm — "
                     "KILL SWITCH ASSERTED (%"PRIu32" consecutive samples)",
                     power_dbm, MAX_TX_POWER_DBM, s_over_limit_count);
            audit_log_record("KILL_SWITCH", "power_overlimit",
                             (int)power_dbm, NULL, 0);
            s_kill_switch_latched = true;
            xEventGroupSetBits(evt_group, kill_bit);
        } else {
            ESP_LOGW(TAG, "TX power elevated: %.1f dBm (%"PRIu32"/%d samples)",
                     power_dbm, s_over_limit_count, OVER_LIMIT_THRESHOLD);
        }
    } else {
        /* Power within limits — reset consecutive counter */
        s_over_limit_count = 0;

        /* If kill switch was latched due to power (not hardware),
         * it stays latched until explicitly cleared via command. */
    }
}

esp_err_t compliance_monitor_clear_kill_switch(EventGroupHandle_t evt_group,
                                               EventBits_t kill_bit)
{
    if (!s_initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    /* Cannot clear if hardware switch is still active */
    if (gpio_get_level(GPIO_HW_KILL_SWITCH) == 0) {
        ESP_LOGW(TAG, "Cannot clear kill switch — hardware switch still active");
        return ESP_ERR_NOT_ALLOWED;
    }

    /* Verify power is currently within limits */
    int voltage_mv = 0;
    esp_err_t ret = read_averaged_voltage(&voltage_mv);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Cannot verify power — ADC read failed");
        return ret;
    }

    float power_dbm = voltage_to_dbm(voltage_mv);
    if (power_dbm > (float)MAX_TX_POWER_DBM) {
        ESP_LOGW(TAG, "Cannot clear kill switch — power still elevated: %.1f dBm",
                 power_dbm);
        return ESP_ERR_NOT_ALLOWED;
    }

    s_kill_switch_latched = false;
    s_over_limit_count = 0;
    xEventGroupClearBits(evt_group, kill_bit);
    ESP_LOGI(TAG, "Kill switch cleared. Current power: %.1f dBm", power_dbm);
    audit_log_record("KILL_SWITCH", "cleared", (int)power_dbm, NULL, 0);

    return ESP_OK;
}

float compliance_monitor_get_power_dbm(void)
{
    return s_last_power_dbm;
}

void compliance_monitor_get_stats(uint32_t *total_samples,
                                  uint32_t *total_violations,
                                  bool *kill_latched)
{
    if (total_samples) *total_samples = s_total_samples;
    if (total_violations) *total_violations = s_total_violations;
    if (kill_latched) *kill_latched = s_kill_switch_latched;
}
