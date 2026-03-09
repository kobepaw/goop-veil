/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 goop-veil contributors
 *
 * main.c — CSI capture detector firmware for goop-veil.
 *
 * This firmware operates in receive-only mode. It captures WiFi
 * Channel State Information (CSI) and reports it over UART for
 * analysis by the host system.
 *
 * The detector passively monitors the RF environment for WiFi sensing
 * activity by analyzing CSI amplitude/phase patterns across subcarriers.
 * It does NOT transmit — all analysis is based on received frames.
 *
 * Architecture:
 *   - Promiscuous mode captures all WiFi frames on the configured channel
 *   - CSI callback extracts per-subcarrier amplitude and phase
 *   - Ring buffer stores recent CSI snapshots
 *   - Reporting task sends CSI data over UART as JSON
 *   - Channel hopping task scans channels 1-11 for coverage
 *
 * SAFETY: This is a passive receiver. It never transmits.
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_err.h"
#include "nvs_flash.h"
#include "driver/uart.h"

static const char *TAG = "veil_detector";

/* ---------------------------------------------------------------------------
 * Configuration
 * --------------------------------------------------------------------------- */

#define REPORT_UART_NUM        UART_NUM_0
#define REPORT_UART_BAUD       (115200)
#define REPORT_UART_BUF_SIZE   (2048)

#ifndef CSI_BUFFER_DEPTH
#define CSI_BUFFER_DEPTH       (128)
#endif

#ifndef CSI_REPORT_INTERVAL_MS
#define CSI_REPORT_INTERVAL_MS (1000)
#endif

/* Maximum CSI data length (ESP32-S3: up to 384 bytes for HT40) */
#define MAX_CSI_DATA_LEN       (384)

/* Channel scan range (US regulatory) */
#define CHANNEL_MIN            (1)
#define CHANNEL_MAX            (11)

/* Channel dwell time during scanning */
#define CHANNEL_DWELL_MS       (200)

/* Task configuration */
#define TASK_STACK_REPORT      (4096)
#define TASK_STACK_SCAN        (2048)
#define TASK_PRIORITY_REPORT   (4)
#define TASK_PRIORITY_SCAN     (3)

/* ---------------------------------------------------------------------------
 * Data structures
 * --------------------------------------------------------------------------- */

/**
 * @brief Single CSI capture record.
 */
typedef struct {
    uint32_t timestamp_ms;               /**< System uptime when captured */
    uint8_t  channel;                    /**< WiFi channel */
    int8_t   rssi;                       /**< RSSI of received frame */
    uint8_t  src_mac[6];                 /**< Source MAC address */
    uint8_t  frame_type;                 /**< 802.11 frame type */
    uint8_t  frame_subtype;              /**< 802.11 frame subtype */
    uint16_t csi_len;                    /**< Length of CSI data */
    int8_t   csi_data[MAX_CSI_DATA_LEN]; /**< Raw CSI (I/Q pairs) */
} csi_record_t;

/**
 * @brief CSI statistics for a channel.
 */
typedef struct {
    uint32_t frame_count;                /**< Total frames received */
    uint32_t csi_count;                  /**< Frames with valid CSI */
    float    avg_rssi;                   /**< Running average RSSI */
    float    csi_variance;               /**< Variance across subcarriers */
    uint32_t last_seen_ms;               /**< Timestamp of last frame */
} channel_stats_t;

/* ---------------------------------------------------------------------------
 * State
 * --------------------------------------------------------------------------- */

static QueueHandle_t s_csi_queue = NULL;
static SemaphoreHandle_t s_stats_mutex = NULL;
static channel_stats_t s_channel_stats[CHANNEL_MAX + 1] = {0};
static uint8_t s_current_channel = 1;
static bool s_scanning_enabled = true;
static uint32_t s_total_csi_records = 0;

/* ---------------------------------------------------------------------------
 * CSI callback (called from WiFi task context)
 * --------------------------------------------------------------------------- */

/**
 * @brief WiFi CSI receive callback.
 *
 * Called by the WiFi driver for each received frame that has CSI data.
 * Copies the CSI data into a record and enqueues it for processing.
 */
static void csi_rx_callback(void *ctx, wifi_csi_info_t *info)
{
    if (info == NULL || info->buf == NULL || info->len == 0) {
        return;
    }

    csi_record_t record = {0};
    record.timestamp_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;
    record.channel = s_current_channel;
    record.rssi = info->rx_ctrl.rssi;

    /* Extract source MAC from the CSI info */
    memcpy(record.src_mac, info->mac, 6);

    /* Copy CSI data (I/Q interleaved) */
    record.csi_len = (info->len > MAX_CSI_DATA_LEN) ? MAX_CSI_DATA_LEN : info->len;
    memcpy(record.csi_data, info->buf, record.csi_len);

    /* Non-waiting enqueue — drop if queue is full (passive capture can
     * tolerate drops; better than stalling the WiFi task) */
    if (s_csi_queue != NULL) {
        BaseType_t sent = xQueueSendFromISR(s_csi_queue, &record, NULL);
        if (sent == pdTRUE) {
            s_total_csi_records++;
        }
    }
}

/**
 * @brief Promiscuous mode receive callback.
 *
 * Captures frame metadata for channel statistics even when CSI is
 * not available for a particular frame.
 */
static void promiscuous_rx_callback(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (buf == NULL) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;

    /* Update channel statistics */
    if (xSemaphoreTake(s_stats_mutex, 0) == pdTRUE) {
        uint8_t ch = s_current_channel;
        if (ch >= CHANNEL_MIN && ch <= CHANNEL_MAX) {
            channel_stats_t *stats = &s_channel_stats[ch];
            stats->frame_count++;
            stats->last_seen_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;

            /* Exponential moving average for RSSI */
            float alpha = 0.1f;
            if (stats->frame_count == 1) {
                stats->avg_rssi = (float)pkt->rx_ctrl.rssi;
            } else {
                stats->avg_rssi = alpha * (float)pkt->rx_ctrl.rssi +
                                  (1.0f - alpha) * stats->avg_rssi;
            }
        }
        xSemaphoreGive(s_stats_mutex);
    }
}

/* ---------------------------------------------------------------------------
 * CSI analysis helpers
 * --------------------------------------------------------------------------- */

/**
 * @brief Compute amplitude from I/Q pair.
 */
static float csi_amplitude(int8_t i_val, int8_t q_val)
{
    return sqrtf((float)(i_val * i_val) + (float)(q_val * q_val));
}

/**
 * @brief Compute variance of CSI amplitudes across subcarriers.
 *
 * High variance may indicate multipath changes or environmental
 * activity affecting the wireless channel.
 *
 * @param csi_data   Raw CSI data (I/Q interleaved)
 * @param csi_len    Length of CSI data in bytes
 * @return Variance of subcarrier amplitudes
 */
static float compute_csi_variance(const int8_t *csi_data, uint16_t csi_len)
{
    if (csi_data == NULL || csi_len < 4) {
        return 0.0f;
    }

    uint16_t num_subcarriers = csi_len / 2;  /* I/Q pairs */
    if (num_subcarriers == 0) return 0.0f;

    /* First pass: compute mean amplitude */
    float sum = 0.0f;
    for (uint16_t i = 0; i < num_subcarriers; i++) {
        sum += csi_amplitude(csi_data[i * 2], csi_data[i * 2 + 1]);
    }
    float mean = sum / (float)num_subcarriers;

    /* Second pass: compute variance */
    float var_sum = 0.0f;
    for (uint16_t i = 0; i < num_subcarriers; i++) {
        float amp = csi_amplitude(csi_data[i * 2], csi_data[i * 2 + 1]);
        float diff = amp - mean;
        var_sum += diff * diff;
    }

    return var_sum / (float)num_subcarriers;
}

/* ---------------------------------------------------------------------------
 * UART reporting
 * --------------------------------------------------------------------------- */

/**
 * @brief Send a CSI report as JSON over UART.
 *
 * Format: {"type":"csi","ts":<ms>,"ch":<n>,"rssi":<n>,"src":"<mac>",
 *          "var":<f>,"subs":<n>}
 */
static void report_csi_record(const csi_record_t *record)
{
    float variance = compute_csi_variance(record->csi_data, record->csi_len);
    uint16_t num_subs = record->csi_len / 2;

    char buf[256];
    int len = snprintf(buf, sizeof(buf),
        "{\"type\":\"csi\",\"ts\":%"PRIu32",\"ch\":%u,\"rssi\":%d,"
        "\"src\":\"%02X:%02X:%02X:%02X:%02X:%02X\","
        "\"var\":%.2f,\"subs\":%u}\n",
        record->timestamp_ms, record->channel, record->rssi,
        record->src_mac[0], record->src_mac[1], record->src_mac[2],
        record->src_mac[3], record->src_mac[4], record->src_mac[5],
        (double)variance, num_subs);

    if (len > 0 && len < (int)sizeof(buf)) {
        uart_write_bytes(REPORT_UART_NUM, buf, len);
    }
}

/**
 * @brief Send channel statistics summary as JSON over UART.
 */
static void report_channel_stats(void)
{
    if (xSemaphoreTake(s_stats_mutex, pdMS_TO_TICKS(50)) != pdTRUE) {
        return;
    }

    char buf[128];
    for (int ch = CHANNEL_MIN; ch <= CHANNEL_MAX; ch++) {
        channel_stats_t *stats = &s_channel_stats[ch];
        if (stats->frame_count > 0) {
            int len = snprintf(buf, sizeof(buf),
                "{\"type\":\"chan_stats\",\"ch\":%d,\"frames\":%"PRIu32","
                "\"csi\":%"PRIu32",\"rssi\":%.1f}\n",
                ch, stats->frame_count, stats->csi_count,
                (double)stats->avg_rssi);

            if (len > 0 && len < (int)sizeof(buf)) {
                uart_write_bytes(REPORT_UART_NUM, buf, len);
            }
        }
    }

    xSemaphoreGive(s_stats_mutex);
}

/* ---------------------------------------------------------------------------
 * FreeRTOS tasks
 * --------------------------------------------------------------------------- */

/**
 * @brief CSI reporting task.
 *
 * Dequeues CSI records and sends them over UART. Also periodically
 * reports channel statistics summaries.
 */
static void report_task(void *pvParameters)
{
    ESP_LOGI(TAG, "CSI report task started");

    uint32_t last_stats_report = 0;

    while (1) {
        csi_record_t record;

        /* Dequeue with timeout */
        if (xQueueReceive(s_csi_queue, &record, pdMS_TO_TICKS(100)) == pdTRUE) {
            report_csi_record(&record);
        }

        /* Periodic channel stats report */
        uint32_t now = xTaskGetTickCount() * portTICK_PERIOD_MS;
        if (now - last_stats_report >= CSI_REPORT_INTERVAL_MS) {
            report_channel_stats();
            last_stats_report = now;
        }
    }
}

/**
 * @brief Channel scanning task.
 *
 * Cycles through channels 1-11 with a configurable dwell time to
 * provide broad RF environment visibility.
 */
static void scan_task(void *pvParameters)
{
    ESP_LOGI(TAG, "Channel scan task started");

    while (1) {
        if (!s_scanning_enabled) {
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }

        for (uint8_t ch = CHANNEL_MIN; ch <= CHANNEL_MAX; ch++) {
            if (!s_scanning_enabled) break;

            esp_err_t ret = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
            if (ret == ESP_OK) {
                s_current_channel = ch;
                ESP_LOGD(TAG, "Scanning channel %u", ch);
            } else {
                ESP_LOGW(TAG, "Failed to set channel %u: %s",
                         ch, esp_err_to_name(ret));
            }

            vTaskDelay(pdMS_TO_TICKS(CHANNEL_DWELL_MS));
        }
    }
}

/* ---------------------------------------------------------------------------
 * Initialization
 * --------------------------------------------------------------------------- */

/**
 * @brief Initialize NVS flash.
 */
static esp_err_t init_nvs(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    return ret;
}

/**
 * @brief Initialize WiFi in station mode for promiscuous capture.
 *
 * Station mode is used because promiscuous mode requires the WiFi
 * stack to be initialized but does not require an active connection.
 * This firmware is receive-only.
 */
static esp_err_t init_wifi_passive(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    /* Set station mode (required for promiscuous) */
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    /* Enable promiscuous mode for passive capture */
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&promiscuous_rx_callback));

    /* Configure and enable CSI collection */
    wifi_csi_config_t csi_cfg = {
        .lltf_en = true,       /* Capture L-LTF (legacy long training field) */
        .htltf_en = true,      /* Capture HT-LTF */
        .stbc_htltf2_en = true,/* Capture STBC HT-LTF2 */
        .ltf_merge_en = true,  /* Merge LTF data */
        .channel_filter_en = false, /* Do not filter by channel */
        .manu_scale = false,   /* Auto scaling */
    };
    ESP_ERROR_CHECK(esp_wifi_set_csi_config(&csi_cfg));
    ESP_ERROR_CHECK(esp_wifi_set_csi_rx_cb(&csi_rx_callback, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_csi(true));

    /* Set initial channel */
    ESP_ERROR_CHECK(esp_wifi_set_channel(CHANNEL_MIN, WIFI_SECOND_CHAN_NONE));
    s_current_channel = CHANNEL_MIN;

    ESP_LOGI(TAG, "WiFi passive capture initialized (promiscuous + CSI)");
    return ESP_OK;
}

/**
 * @brief Initialize UART for reporting.
 */
static esp_err_t init_report_uart(void)
{
    /* UART0 is typically the default console — reuse it for JSON output */
    /* If separate UART is needed, change REPORT_UART_NUM and configure pins */

    /* TODO: If using a separate UART (not UART0), configure pins and
     * install driver here. UART0 is already configured by the ESP-IDF
     * logging system. */

    return ESP_OK;
}

/* ---------------------------------------------------------------------------
 * Application entry point
 * --------------------------------------------------------------------------- */

void app_main(void)
{
    ESP_LOGI(TAG, "=== goop-veil detector firmware ===");
    ESP_LOGI(TAG, "Build: %s %s", __DATE__, __TIME__);
    ESP_LOGI(TAG, "Mode: PASSIVE RECEIVE ONLY (no TX)");

    /* Create synchronization primitives */
    s_csi_queue = xQueueCreate(CSI_BUFFER_DEPTH, sizeof(csi_record_t));
    s_stats_mutex = xSemaphoreCreateMutex();
    configASSERT(s_csi_queue != NULL);
    configASSERT(s_stats_mutex != NULL);

    /* Initialize subsystems */
    ESP_ERROR_CHECK(init_nvs());
    ESP_LOGI(TAG, "NVS initialized");

    ESP_ERROR_CHECK(init_report_uart());
    ESP_LOGI(TAG, "Report UART initialized");

    ESP_ERROR_CHECK(init_wifi_passive());
    ESP_LOGI(TAG, "Passive WiFi capture active");

    /* Spawn tasks */
    xTaskCreate(report_task, "csi_report", TASK_STACK_REPORT,
                NULL, TASK_PRIORITY_REPORT, NULL);

    xTaskCreate(scan_task, "chan_scan", TASK_STACK_SCAN,
                NULL, TASK_PRIORITY_SCAN, NULL);

    ESP_LOGI(TAG, "Detector operational. Scanning channels %d-%d.",
             CHANNEL_MIN, CHANNEL_MAX);
}
