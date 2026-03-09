/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 goop-veil contributors
 *
 * legitimate_functions.c — Mesh AP, environmental sensors, and FTM ranging.
 *
 * This module manages the device's legitimate WiFi functions:
 *   - Mesh network AP operation (beaconing, station management)
 *   - Environmental sensor data collection (temperature, humidity via I2C)
 *   - Fine Timing Measurement (FTM) for indoor positioning
 *
 * These functions provide the device's primary operational purpose
 * and justify its RF presence on the channel.
 */

#include <string.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_log.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/i2c.h"

#include "legitimate_functions.h"
#include "frame_filter.h"
#include "audit_log.h"

static const char *TAG = "legit_fn";

/* ---------------------------------------------------------------------------
 * Mesh AP configuration
 * --------------------------------------------------------------------------- */

#define MESH_AP_SSID_PREFIX   "VEIL-MESH-"
#define MESH_AP_MAX_CONN      (4)
#define MESH_BEACON_INTERVAL  (100)   /* ms */

/* ---------------------------------------------------------------------------
 * I2C sensor configuration (e.g., SHT31 temp/humidity)
 * --------------------------------------------------------------------------- */

#define I2C_MASTER_NUM         I2C_NUM_0
#define I2C_MASTER_SDA_IO      GPIO_NUM_8
#define I2C_MASTER_SCL_IO      GPIO_NUM_9
#define I2C_MASTER_FREQ_HZ     (100000)
#define SHT31_SENSOR_ADDR      (0x44)

/* ---------------------------------------------------------------------------
 * FTM configuration
 * --------------------------------------------------------------------------- */

#define FTM_FRMS_PER_BURST     (16)
#define FTM_BURST_PERIOD_MS    (2)

/* ---------------------------------------------------------------------------
 * State
 * --------------------------------------------------------------------------- */

typedef struct {
    float temperature_c;
    float humidity_pct;
    bool  valid;
    uint32_t timestamp_ms;
} sensor_reading_t;

static sensor_reading_t s_last_reading = {0};
static bool s_initialized = false;
static uint32_t s_tick_count = 0;

/* ---------------------------------------------------------------------------
 * Sensor I/O (stub — requires real I2C sensor hardware)
 * --------------------------------------------------------------------------- */

/**
 * @brief Initialize I2C master for sensor communication.
 *
 * @return ESP_OK on success
 */
static esp_err_t init_i2c_sensors(void)
{
    i2c_config_t conf = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = I2C_MASTER_SDA_IO,
        .scl_io_num = I2C_MASTER_SCL_IO,
        .sda_pullup_en = GPIO_PULLUP_ENABLE,
        .scl_pullup_en = GPIO_PULLUP_ENABLE,
        .master.clk_speed = I2C_MASTER_FREQ_HZ,
    };

    esp_err_t ret = i2c_param_config(I2C_MASTER_NUM, &conf);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "I2C config failed (sensor may not be attached): %s",
                 esp_err_to_name(ret));
        return ret;
    }

    ret = i2c_driver_install(I2C_MASTER_NUM, conf.mode, 0, 0, 0);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "I2C driver install failed: %s", esp_err_to_name(ret));
    }
    return ret;
}

/**
 * @brief Read temperature and humidity from SHT31 sensor.
 *
 * @param[out] reading  Pointer to receive sensor data
 * @return ESP_OK on success
 */
static esp_err_t read_sensor(sensor_reading_t *reading)
{
    if (reading == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    /* TODO: Implement actual SHT31 I2C read sequence:
     *   1. Send measurement command (0x2C06 for high repeatability)
     *   2. Wait ~15ms for measurement
     *   3. Read 6 bytes (temp MSB, LSB, CRC, hum MSB, LSB, CRC)
     *   4. Verify CRC-8 checksums
     *   5. Convert raw values to temperature (C) and humidity (%) */

    reading->valid = false;
    reading->timestamp_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;

    ESP_LOGD(TAG, "Sensor read stub — no hardware attached");
    return ESP_ERR_NOT_FOUND;
}

/* ---------------------------------------------------------------------------
 * FTM ranging (stub — requires FTM-capable responder)
 * --------------------------------------------------------------------------- */

/**
 * @brief Initiate FTM ranging session with a responder.
 *
 * Fine Timing Measurement provides sub-meter indoor positioning
 * using round-trip time measurement of WiFi frames.
 *
 * @param responder_mac  MAC address of FTM responder
 * @param channel        WiFi channel of responder
 * @return ESP_OK on success
 */
static esp_err_t initiate_ftm_ranging(const uint8_t *responder_mac,
                                       uint8_t channel)
{
    if (responder_mac == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    /* TODO: Implement FTM initiator:
     *   1. Configure FTM initiator with target responder MAC
     *   2. Set burst parameters (FTM_FRMS_PER_BURST frames, FTM_BURST_PERIOD_MS)
     *   3. Register FTM report callback
     *   4. Initiate FTM session
     *   5. Parse FTM report for RTT and estimated distance
     *
     * esp_wifi_ftm_initiate_session() is available in ESP-IDF >= 5.0
     * with CONFIG_ESP_WIFI_FTM_ENABLE=1 */

    ESP_LOGI(TAG, "FTM ranging stub: responder=" MACSTR " ch=%u",
             MAC2STR(responder_mac), channel);

    return ESP_ERR_NOT_SUPPORTED;
}

/* ---------------------------------------------------------------------------
 * Mesh AP management
 * --------------------------------------------------------------------------- */

/**
 * @brief Handle new station association event.
 *
 * Adds the station to the frame filter's association table so that
 * management frames can be properly addressed.
 *
 * @param mac  MAC address of the newly associated station
 */
static void on_station_connected(const uint8_t *mac)
{
    ESP_LOGI(TAG, "Mesh station connected: " MACSTR, MAC2STR(mac));

    /* Register with frame filter so deauth is permitted if needed */
    esp_err_t ret = frame_filter_add_station(mac);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Failed to add station to filter table: %s",
                 esp_err_to_name(ret));
    }

    audit_log_record("MESH_CONNECT", "station_joined", 0, mac, 6);
}

/**
 * @brief Handle station disassociation event.
 *
 * Removes the station from the frame filter's association table.
 *
 * @param mac  MAC address of the departed station
 */
static void on_station_disconnected(const uint8_t *mac)
{
    ESP_LOGI(TAG, "Mesh station disconnected: " MACSTR, MAC2STR(mac));

    esp_err_t ret = frame_filter_remove_station(mac);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Failed to remove station from filter table: %s",
                 esp_err_to_name(ret));
    }

    audit_log_record("MESH_DISCONNECT", "station_left", 0, mac, 6);
}

/* ---------------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------------- */

esp_err_t legitimate_functions_init(void)
{
    if (s_initialized) {
        return ESP_OK;
    }

    /* Initialize I2C sensors (non-fatal if no hardware attached) */
    esp_err_t ret = init_i2c_sensors();
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Sensors not available — continuing without sensor data");
    }

    /* TODO: Register WiFi event callbacks for station connect/disconnect
     * to call on_station_connected() and on_station_disconnected() */

    /* TODO: Initialize mesh discovery (mDNS or custom beacon IE) */

    s_initialized = true;
    ESP_LOGI(TAG, "Legitimate functions initialized (mesh AP, sensors, FTM)");

    return ESP_OK;
}

void legitimate_functions_tick(void)
{
    if (!s_initialized) {
        return;
    }

    s_tick_count++;

    /* Read sensors every 10 ticks (~1 second at 100ms tick rate) */
    if ((s_tick_count % 10) == 0) {
        sensor_reading_t reading = {0};
        esp_err_t ret = read_sensor(&reading);
        if (ret == ESP_OK && reading.valid) {
            s_last_reading = reading;
            ESP_LOGI(TAG, "Sensor: %.1f C, %.1f%% RH",
                     reading.temperature_c, reading.humidity_pct);
        }
    }

    /* TODO: Periodic mesh peer discovery via beacon parsing */
    /* TODO: FTM ranging to known mesh peers for positioning */
    /* TODO: Mesh routing table maintenance */
}

esp_err_t legitimate_functions_get_sensor_data(float *temperature_c,
                                                float *humidity_pct)
{
    if (!s_last_reading.valid) {
        return ESP_ERR_NOT_FOUND;
    }

    if (temperature_c) *temperature_c = s_last_reading.temperature_c;
    if (humidity_pct) *humidity_pct = s_last_reading.humidity_pct;

    return ESP_OK;
}

int legitimate_functions_get_mesh_peer_count(void)
{
    return frame_filter_get_station_count();
}
