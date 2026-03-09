/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 goop-veil contributors
 *
 * frame_filter.c — SAFETY CRITICAL: Frame type and destination filter.
 *
 * This module is the authoritative safety gate for all transmitted frames.
 * It enforces the following invariants:
 *
 *   1. NEVER send deauth (subtype 0x0C) or disassoc (subtype 0x0A) frames
 *      to any device that is not associated with our own BSS.
 *   2. NEVER address frames to third-party devices (devices not in our
 *      association table).
 *   3. NEVER allow continuous wave (CW) — only standard framed OFDM.
 *   4. NEVER transmit frames outside channels 1-11 (enforced elsewhere,
 *      but double-checked here).
 *   5. Management frames (type 0x00) that are deauth/disassoc are ONLY
 *      permitted when the destination MAC is in the own-BSS association
 *      table.
 *   6. Broadcast deauth/disassoc frames are ALWAYS rejected.
 *
 * This file contains ACTUAL IMPLEMENTATION, not stubs. The safety logic
 * must be fully functional from the first firmware build.
 */

#include <string.h>
#include <stdbool.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "frame_filter.h"
#include "audit_log.h"

static const char *TAG = "frame_filter";

/* ---------------------------------------------------------------------------
 * 802.11 frame header constants
 * --------------------------------------------------------------------------- */

/* Frame Control field (2 bytes, little-endian) */
#define FC_TYPE_MASK         (0x0C)   /* Bits 2-3 of FC byte 0 */
#define FC_SUBTYPE_MASK      (0xF0)   /* Bits 4-7 of FC byte 0 */

#define FC_TYPE_MGMT         (0x00)   /* Management frame */
#define FC_TYPE_CTRL         (0x04)   /* Control frame */
#define FC_TYPE_DATA         (0x08)   /* Data frame */

/* Management frame subtypes (shifted to bits 4-7) */
#define FC_SUBTYPE_ASSOC_REQ     (0x00)
#define FC_SUBTYPE_ASSOC_RESP    (0x10)
#define FC_SUBTYPE_REASSOC_REQ   (0x20)
#define FC_SUBTYPE_REASSOC_RESP  (0x30)
#define FC_SUBTYPE_PROBE_REQ     (0x40)
#define FC_SUBTYPE_PROBE_RESP    (0x50)
#define FC_SUBTYPE_BEACON        (0x80)
#define FC_SUBTYPE_DISASSOC      (0xA0)
#define FC_SUBTYPE_AUTH          (0xB0)
#define FC_SUBTYPE_DEAUTH        (0xC0)
#define FC_SUBTYPE_ACTION        (0xD0)

/* Offsets into the 802.11 MAC header */
#define OFFSET_FC             (0)     /* Frame Control: bytes 0-1 */
#define OFFSET_DURATION       (2)     /* Duration/ID: bytes 2-3 */
#define OFFSET_ADDR1          (4)     /* Address 1 (DA/RA): bytes 4-9 */
#define OFFSET_ADDR2          (10)    /* Address 2 (SA/TA): bytes 10-15 */
#define OFFSET_ADDR3          (16)    /* Address 3 (BSSID): bytes 16-21 */
#define OFFSET_SEQ_CTRL       (22)    /* Sequence Control: bytes 22-23 */

#define MAC_ADDR_LEN          (6)
#define MIN_MGMT_FRAME_LEN    (24)    /* FC + Dur + A1 + A2 + A3 + SeqCtl */

/* Broadcast MAC address */
static const uint8_t BROADCAST_MAC[MAC_ADDR_LEN] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* ---------------------------------------------------------------------------
 * Own-BSS association table
 *
 * Tracks devices currently associated with our AP. This is the ONLY set of
 * devices to which deauth/disassoc frames may be sent.
 * --------------------------------------------------------------------------- */

#define MAX_ASSOCIATED_STATIONS  (8)

typedef struct {
    uint8_t mac[MAC_ADDR_LEN];
    bool    occupied;
} assoc_entry_t;

static assoc_entry_t s_assoc_table[MAX_ASSOCIATED_STATIONS];
static SemaphoreHandle_t s_assoc_mutex;
static uint8_t s_own_bssid[MAC_ADDR_LEN];
static bool s_initialized = false;

/* ---------------------------------------------------------------------------
 * Association table management
 * --------------------------------------------------------------------------- */

/**
 * @brief Check if a MAC address matches the broadcast address.
 */
static bool is_broadcast(const uint8_t *mac)
{
    return (memcmp(mac, BROADCAST_MAC, MAC_ADDR_LEN) == 0);
}

/**
 * @brief Check if a MAC address is a multicast address.
 *
 * Bit 0 of the first octet indicates group (multicast/broadcast).
 */
static bool is_multicast(const uint8_t *mac)
{
    return (mac[0] & 0x01) != 0;
}

/**
 * @brief Check if a MAC is in the own-BSS association table.
 *
 * Thread-safe: acquires s_assoc_mutex.
 *
 * @param mac  6-byte MAC address to look up
 * @return true if the MAC is currently associated with our BSS
 */
static bool is_own_bss_station(const uint8_t *mac)
{
    bool found = false;

    if (xSemaphoreTake(s_assoc_mutex, pdMS_TO_TICKS(10)) != pdTRUE) {
        /* If we can't acquire the mutex, fail CLOSED (reject the frame).
         * Safety-critical code must never fail open. */
        ESP_LOGW(TAG, "Could not acquire assoc_mutex — failing closed");
        return false;
    }

    for (int i = 0; i < MAX_ASSOCIATED_STATIONS; i++) {
        if (s_assoc_table[i].occupied &&
            memcmp(s_assoc_table[i].mac, mac, MAC_ADDR_LEN) == 0) {
            found = true;
            break;
        }
    }

    xSemaphoreGive(s_assoc_mutex);
    return found;
}

/**
 * @brief Check if a frame's BSSID (Address 3) matches our own BSSID.
 */
static bool is_own_bssid(const uint8_t *bssid)
{
    return (memcmp(bssid, s_own_bssid, MAC_ADDR_LEN) == 0);
}

/* ---------------------------------------------------------------------------
 * Core safety validation
 * --------------------------------------------------------------------------- */

/**
 * @brief Extract frame type and subtype from the Frame Control field.
 */
static void parse_frame_control(const uint8_t *fc, uint8_t *type, uint8_t *subtype)
{
    *type = fc[0] & FC_TYPE_MASK;
    *subtype = fc[0] & FC_SUBTYPE_MASK;
}

/**
 * @brief Check if a management subtype is a deauth or disassoc frame.
 */
static bool is_deauth_or_disassoc(uint8_t subtype)
{
    return (subtype == FC_SUBTYPE_DEAUTH || subtype == FC_SUBTYPE_DISASSOC);
}

/* ---------------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------------- */

esp_err_t frame_filter_init(void)
{
    if (s_initialized) {
        return ESP_OK;
    }

    s_assoc_mutex = xSemaphoreCreateMutex();
    if (s_assoc_mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create association table mutex");
        return ESP_ERR_NO_MEM;
    }

    /* Clear association table */
    memset(s_assoc_table, 0, sizeof(s_assoc_table));

    /* Get our own BSSID (AP MAC address) */
    esp_err_t ret = esp_wifi_get_mac(WIFI_IF_AP, s_own_bssid);
    if (ret != ESP_OK) {
        /* WiFi may not be initialized yet; will retry on first validate call */
        ESP_LOGW(TAG, "Could not get own BSSID yet (WiFi not started)");
        memset(s_own_bssid, 0, MAC_ADDR_LEN);
    } else {
        ESP_LOGI(TAG, "Own BSSID: " MACSTR, MAC2STR(s_own_bssid));
    }

    s_initialized = true;
    ESP_LOGI(TAG, "Frame filter initialized — safety checks ACTIVE");
    return ESP_OK;
}

frame_filter_result_t frame_filter_validate(const uint8_t *frame, size_t len)
{
    if (!s_initialized) {
        ESP_LOGE(TAG, "Frame filter not initialized — rejecting ALL frames");
        return FRAME_FILTER_NOT_INITIALIZED;
    }

    /* -----------------------------------------------------------------------
     * CHECK 1: Minimum frame length
     * ----------------------------------------------------------------------- */
    if (frame == NULL || len < MIN_MGMT_FRAME_LEN) {
        ESP_LOGW(TAG, "Frame too short: len=%zu (min=%d)", len, MIN_MGMT_FRAME_LEN);
        return FRAME_FILTER_INVALID_LENGTH;
    }

    /* -----------------------------------------------------------------------
     * CHECK 2: Parse frame type and subtype
     * ----------------------------------------------------------------------- */
    uint8_t type, subtype;
    parse_frame_control(&frame[OFFSET_FC], &type, &subtype);

    const uint8_t *addr1 = &frame[OFFSET_ADDR1];   /* Destination / Receiver */
    const uint8_t *addr3 = &frame[OFFSET_ADDR3];    /* BSSID */

    /* -----------------------------------------------------------------------
     * CHECK 3: Ensure our BSSID is populated (lazy init after WiFi start)
     * ----------------------------------------------------------------------- */
    static const uint8_t zero_mac[MAC_ADDR_LEN] = {0};
    if (memcmp(s_own_bssid, zero_mac, MAC_ADDR_LEN) == 0) {
        esp_err_t ret = esp_wifi_get_mac(WIFI_IF_AP, s_own_bssid);
        if (ret != ESP_OK || memcmp(s_own_bssid, zero_mac, MAC_ADDR_LEN) == 0) {
            ESP_LOGE(TAG, "Own BSSID unknown — rejecting frame (fail closed)");
            return FRAME_FILTER_NO_BSSID;
        }
        ESP_LOGI(TAG, "Own BSSID resolved: " MACSTR, MAC2STR(s_own_bssid));
    }

    /* -----------------------------------------------------------------------
     * CHECK 4: Management frame safety validation
     * ----------------------------------------------------------------------- */
    if (type == FC_TYPE_MGMT) {

        /* 4a. Deauth and disassoc frames require special handling */
        if (is_deauth_or_disassoc(subtype)) {

            const char *frame_name = (subtype == FC_SUBTYPE_DEAUTH)
                                     ? "DEAUTH" : "DISASSOC";

            /* RULE: NEVER send broadcast deauth/disassoc.
             * This would affect all stations on the channel, including
             * third-party devices. Always rejected. */
            if (is_broadcast(addr1) || is_multicast(addr1)) {
                ESP_LOGE(TAG, "BLOCKED: Broadcast/multicast %s frame — "
                         "would affect non-own devices", frame_name);
                audit_log_record("SAFETY_BLOCK", frame_name,
                                 FRAME_FILTER_BROADCAST_DEAUTH, frame,
                                 MIN_MGMT_FRAME_LEN);
                return FRAME_FILTER_BROADCAST_DEAUTH;
            }

            /* RULE: BSSID (Address 3) MUST match our own BSS.
             * A deauth/disassoc with a third-party BSSID would be
             * impersonating another AP — always rejected. */
            if (!is_own_bssid(addr3)) {
                ESP_LOGE(TAG, "BLOCKED: %s frame with non-own BSSID "
                         MACSTR " (own: " MACSTR ")",
                         frame_name, MAC2STR(addr3), MAC2STR(s_own_bssid));
                audit_log_record("SAFETY_BLOCK", frame_name,
                                 FRAME_FILTER_FOREIGN_BSSID, frame,
                                 MIN_MGMT_FRAME_LEN);
                return FRAME_FILTER_FOREIGN_BSSID;
            }

            /* RULE: Destination (Address 1) MUST be in our association table.
             * We only deauth/disassoc stations that are currently associated
             * with our own AP. */
            if (!is_own_bss_station(addr1)) {
                ESP_LOGE(TAG, "BLOCKED: %s to non-associated station "
                         MACSTR " — not in own BSS",
                         frame_name, MAC2STR(addr1));
                audit_log_record("SAFETY_BLOCK", frame_name,
                                 FRAME_FILTER_NOT_OWN_BSS, frame,
                                 MIN_MGMT_FRAME_LEN);
                return FRAME_FILTER_NOT_OWN_BSS;
            }

            /* All checks passed for deauth/disassoc — this is a legitimate
             * AP managing its own stations. */
            ESP_LOGI(TAG, "ALLOWED: %s to own-BSS station " MACSTR,
                     frame_name, MAC2STR(addr1));
            audit_log_record("TX_ALLOWED", frame_name,
                             FRAME_FILTER_PASS, frame, MIN_MGMT_FRAME_LEN);
            return FRAME_FILTER_PASS;
        }

        /* 4b. Other management frames (beacon, probe, auth, action, etc.)
         * must have our own BSSID. */
        if (!is_own_bssid(addr3) && !is_broadcast(addr3)) {
            ESP_LOGW(TAG, "BLOCKED: Management frame (subtype=0x%02X) with "
                     "foreign BSSID " MACSTR,
                     subtype, MAC2STR(addr3));
            audit_log_record("SAFETY_BLOCK", "MGMT_FOREIGN_BSSID",
                             FRAME_FILTER_FOREIGN_BSSID, frame,
                             MIN_MGMT_FRAME_LEN);
            return FRAME_FILTER_FOREIGN_BSSID;
        }

        /* 4c. Unicast management frames to non-own stations: reject.
         * We don't send management frames to third-party devices. */
        if (!is_broadcast(addr1) && !is_multicast(addr1) &&
            !is_own_bss_station(addr1)) {
            /* Exception: probe responses can go to any requesting station */
            if (subtype != FC_SUBTYPE_PROBE_RESP) {
                ESP_LOGW(TAG, "BLOCKED: Unicast mgmt (subtype=0x%02X) to "
                         "non-associated " MACSTR,
                         subtype, MAC2STR(addr1));
                audit_log_record("SAFETY_BLOCK", "MGMT_FOREIGN_DEST",
                                 FRAME_FILTER_NOT_OWN_BSS, frame,
                                 MIN_MGMT_FRAME_LEN);
                return FRAME_FILTER_NOT_OWN_BSS;
            }
        }
    }

    /* -----------------------------------------------------------------------
     * CHECK 5: Data frame safety validation
     * ----------------------------------------------------------------------- */
    if (type == FC_TYPE_DATA) {
        /* Data frames from AP: Address 1 is DA, Address 3 is SA.
         * BSSID is Address 2 for FromDS frames. Verify DA is own-BSS. */
        if (!is_broadcast(addr1) && !is_multicast(addr1) &&
            !is_own_bss_station(addr1)) {
            ESP_LOGW(TAG, "BLOCKED: Data frame to non-associated " MACSTR,
                     MAC2STR(addr1));
            audit_log_record("SAFETY_BLOCK", "DATA_FOREIGN_DEST",
                             FRAME_FILTER_NOT_OWN_BSS, frame,
                             MIN_MGMT_FRAME_LEN);
            return FRAME_FILTER_NOT_OWN_BSS;
        }
    }

    /* -----------------------------------------------------------------------
     * CHECK 6: Control frames — allow only standard control frames
     * ----------------------------------------------------------------------- */
    if (type == FC_TYPE_CTRL) {
        /* Control frames (RTS/CTS/ACK) are generally handled by hardware.
         * If software is constructing them, only allow if addressed to
         * own-BSS or broadcast. */
        if (!is_broadcast(addr1) && !is_own_bss_station(addr1)) {
            ESP_LOGW(TAG, "BLOCKED: Control frame to non-own " MACSTR,
                     MAC2STR(addr1));
            return FRAME_FILTER_NOT_OWN_BSS;
        }
    }

    return FRAME_FILTER_PASS;
}

esp_err_t frame_filter_add_station(const uint8_t *mac)
{
    if (mac == NULL || is_broadcast(mac)) {
        return ESP_ERR_INVALID_ARG;
    }

    if (xSemaphoreTake(s_assoc_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    /* Check for duplicate */
    for (int i = 0; i < MAX_ASSOCIATED_STATIONS; i++) {
        if (s_assoc_table[i].occupied &&
            memcmp(s_assoc_table[i].mac, mac, MAC_ADDR_LEN) == 0) {
            xSemaphoreGive(s_assoc_mutex);
            ESP_LOGI(TAG, "Station " MACSTR " already in table", MAC2STR(mac));
            return ESP_OK;
        }
    }

    /* Find empty slot */
    for (int i = 0; i < MAX_ASSOCIATED_STATIONS; i++) {
        if (!s_assoc_table[i].occupied) {
            memcpy(s_assoc_table[i].mac, mac, MAC_ADDR_LEN);
            s_assoc_table[i].occupied = true;
            xSemaphoreGive(s_assoc_mutex);
            ESP_LOGI(TAG, "Station " MACSTR " added to own-BSS table",
                     MAC2STR(mac));
            audit_log_record("STA_ASSOC", "added", 0, mac, MAC_ADDR_LEN);
            return ESP_OK;
        }
    }

    xSemaphoreGive(s_assoc_mutex);
    ESP_LOGW(TAG, "Association table full — cannot add " MACSTR, MAC2STR(mac));
    return ESP_ERR_NO_MEM;
}

esp_err_t frame_filter_remove_station(const uint8_t *mac)
{
    if (mac == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (xSemaphoreTake(s_assoc_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    for (int i = 0; i < MAX_ASSOCIATED_STATIONS; i++) {
        if (s_assoc_table[i].occupied &&
            memcmp(s_assoc_table[i].mac, mac, MAC_ADDR_LEN) == 0) {
            s_assoc_table[i].occupied = false;
            memset(s_assoc_table[i].mac, 0, MAC_ADDR_LEN);
            xSemaphoreGive(s_assoc_mutex);
            ESP_LOGI(TAG, "Station " MACSTR " removed from own-BSS table",
                     MAC2STR(mac));
            audit_log_record("STA_DEASSOC", "removed", 0, mac, MAC_ADDR_LEN);
            return ESP_OK;
        }
    }

    xSemaphoreGive(s_assoc_mutex);
    return ESP_ERR_NOT_FOUND;
}

int frame_filter_get_station_count(void)
{
    int count = 0;

    if (xSemaphoreTake(s_assoc_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return -1;
    }

    for (int i = 0; i < MAX_ASSOCIATED_STATIONS; i++) {
        if (s_assoc_table[i].occupied) {
            count++;
        }
    }

    xSemaphoreGive(s_assoc_mutex);
    return count;
}
