/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 goop-veil contributors
 *
 * wifi_tx.c — WiFi frame transmission for RF environment management.
 *
 * All frames pass through the frame filter (frame_filter.c) before
 * transmission. The frame filter is the authoritative safety gate —
 * this module MUST NOT bypass it under any circumstances.
 *
 * Transmitted frames are standard OFDM 802.11 management/data frames.
 * Continuous wave (CW) transmission is never used.
 *
 * SAFETY INVARIANTS:
 *   - Every frame passes frame_filter_validate() before esp_wifi_80211_tx()
 *   - TX power is checked via power_limiter before each burst
 *   - Channel is validated to be within 1-11 (US regulatory domain)
 *   - All frames are addressed only to own-BSS devices
 */

#include <string.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "wifi_tx.h"
#include "frame_filter.h"
#include "power_limiter.h"
#include "audit_log.h"

static const char *TAG = "wifi_tx";

/* Maximum 802.11 frame length */
#define MAX_FRAME_LEN  (2346)

/* Minimum valid 802.11 header length (FC + Duration + Addr1) */
#define MIN_HEADER_LEN (10)

/* TX statistics */
static uint32_t s_frames_sent = 0;
static uint32_t s_frames_rejected = 0;

/* ---------------------------------------------------------------------------
 * Internal helpers
 * --------------------------------------------------------------------------- */

/**
 * @brief Validate channel is within allowed range.
 *
 * @param channel  WiFi channel number
 * @return true if channel is 1-11 (US regulatory domain)
 */
static bool is_channel_valid(uint8_t channel)
{
    return (channel >= CHANNEL_MIN && channel <= CHANNEL_MAX);
}

/**
 * @brief Get the current operating channel.
 *
 * @param[out] channel  Pointer to receive channel number
 * @return ESP_OK on success
 */
static esp_err_t get_current_channel(uint8_t *channel)
{
    uint8_t primary;
    wifi_second_chan_t secondary;
    esp_err_t ret = esp_wifi_get_channel(&primary, &secondary);
    if (ret == ESP_OK) {
        *channel = primary;
    }
    return ret;
}

/* ---------------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------------- */

esp_err_t wifi_tx_send_frame(const uint8_t *frame, size_t len)
{
    if (frame == NULL || len < MIN_HEADER_LEN || len > MAX_FRAME_LEN) {
        ESP_LOGE(TAG, "Invalid frame: ptr=%p len=%zu", frame, len);
        s_frames_rejected++;
        return ESP_ERR_INVALID_ARG;
    }

    /* SAFETY CHECK 1: Verify current channel is within allowed range */
    uint8_t channel = 0;
    esp_err_t ret = get_current_channel(&channel);
    if (ret != ESP_OK || !is_channel_valid(channel)) {
        ESP_LOGE(TAG, "Channel validation failed: ch=%u (allowed %d-%d)",
                 channel, CHANNEL_MIN, CHANNEL_MAX);
        audit_log_record("TX_REJECTED", "channel_out_of_range",
                         channel, frame, MIN_HEADER_LEN);
        s_frames_rejected++;
        return ESP_ERR_NOT_ALLOWED;
    }

    /* SAFETY CHECK 2: Verify TX power is within limits */
    if (!power_limiter_check()) {
        ESP_LOGE(TAG, "TX power exceeds limit — frame dropped");
        audit_log_record("TX_REJECTED", "power_limit_exceeded",
                         channel, frame, MIN_HEADER_LEN);
        s_frames_rejected++;
        return ESP_ERR_NOT_ALLOWED;
    }

    /* SAFETY CHECK 3: Frame filter — the authoritative safety gate.
     * This validates frame type, destination address, and BSS ownership. */
    frame_filter_result_t filter_result = frame_filter_validate(frame, len);
    if (filter_result != FRAME_FILTER_PASS) {
        ESP_LOGE(TAG, "Frame filter rejected: result=%d", filter_result);
        audit_log_record("TX_REJECTED", "frame_filter",
                         filter_result, frame, MIN_HEADER_LEN);
        s_frames_rejected++;
        return ESP_ERR_NOT_ALLOWED;
    }

    /* All safety checks passed — transmit the frame.
     * esp_wifi_80211_tx sends a single standard OFDM frame (never CW). */
    ret = esp_wifi_80211_tx(WIFI_IF_AP, frame, len, true);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_80211_tx failed: %s", esp_err_to_name(ret));
        s_frames_rejected++;
        return ret;
    }

    s_frames_sent++;

    /* Log every Nth frame to avoid flooding audit log */
    if ((s_frames_sent % 100) == 0) {
        ESP_LOGI(TAG, "TX stats: sent=%"PRIu32" rejected=%"PRIu32,
                 s_frames_sent, s_frames_rejected);
    }

    return ESP_OK;
}

esp_err_t wifi_tx_set_channel(uint8_t channel)
{
    if (!is_channel_valid(channel)) {
        ESP_LOGE(TAG, "Refusing to set invalid channel %u (allowed %d-%d)",
                 channel, CHANNEL_MIN, CHANNEL_MAX);
        audit_log_record("CHANNEL_REJECTED", "out_of_range",
                         channel, NULL, 0);
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t ret = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "Channel set to %u", channel);
        audit_log_record("CHANNEL_SET", "ok", channel, NULL, 0);
    }
    return ret;
}

void wifi_tx_get_stats(uint32_t *sent, uint32_t *rejected)
{
    if (sent) *sent = s_frames_sent;
    if (rejected) *rejected = s_frames_rejected;
}

esp_err_t wifi_tx_reset_stats(void)
{
    s_frames_sent = 0;
    s_frames_rejected = 0;
    ESP_LOGI(TAG, "TX statistics reset");
    return ESP_OK;
}
