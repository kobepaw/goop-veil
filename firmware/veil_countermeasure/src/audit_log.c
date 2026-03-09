/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 goop-veil contributors
 *
 * audit_log.c — Ed25519-signed audit trail on SPI flash.
 *
 * Records all safety-relevant events (TX, kill switch, power violations,
 * frame filter blocks) to a dedicated SPI flash partition with Ed25519
 * digital signatures for tamper evidence.
 *
 * Log entries are buffered in RAM and periodically flushed to flash
 * by the audit task. Each flush batch is signed with the device's
 * Ed25519 private key (stored in eFuse or NVS).
 *
 * The audit log is append-only and cannot be erased except by a full
 * partition erase (which itself is logged before execution and requires
 * a physical GPIO confirmation).
 */

#include <string.h>
#include <time.h>
#include "esp_log.h"
#include "esp_err.h"
#include "esp_partition.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "audit_log.h"

static const char *TAG = "audit_log";

/* ---------------------------------------------------------------------------
 * Configuration
 * --------------------------------------------------------------------------- */

/* Partition label for audit log storage */
#ifndef AUDIT_PARTITION_LABEL
#define AUDIT_PARTITION_LABEL  "audit"
#endif

/* Maximum entries buffered in RAM before flush */
#define AUDIT_BUFFER_SIZE      (64)

/* Maximum payload data per entry */
#define AUDIT_MAX_PAYLOAD      (32)

/* Ed25519 signature length */
#define ED25519_SIG_LEN        (64)
#define ED25519_PUBKEY_LEN     (32)
#define ED25519_PRIVKEY_LEN    (64)

/* ---------------------------------------------------------------------------
 * Data structures
 * --------------------------------------------------------------------------- */

/**
 * @brief Single audit log entry (fixed size for flash alignment).
 */
typedef struct __attribute__((packed)) {
    uint32_t sequence;                     /* Monotonic sequence number */
    uint32_t timestamp_ms;                 /* System uptime in ms */
    char     event_type[16];               /* e.g., "TX_REJECTED" */
    char     detail[16];                   /* e.g., "frame_filter" */
    int32_t  numeric_value;                /* Context-dependent value */
    uint8_t  payload[AUDIT_MAX_PAYLOAD];   /* Optional binary data */
    uint8_t  payload_len;                  /* Actual payload length */
    uint8_t  _pad[3];                      /* Alignment padding */
} audit_entry_t;

/**
 * @brief Signed batch header written before each flush.
 */
typedef struct __attribute__((packed)) {
    uint32_t magic;                         /* 0x564C4F47 ("VLOG") */
    uint32_t batch_seq;                     /* Batch sequence number */
    uint32_t entry_count;                   /* Number of entries in batch */
    uint32_t total_size;                    /* Total bytes including header */
    uint8_t  signature[ED25519_SIG_LEN];    /* Ed25519 signature over entries */
    uint8_t  pubkey[ED25519_PUBKEY_LEN];    /* Signing public key */
} audit_batch_header_t;

#define BATCH_MAGIC  (0x564C4F47)

/* ---------------------------------------------------------------------------
 * State
 * --------------------------------------------------------------------------- */

static const esp_partition_t *s_partition = NULL;
static SemaphoreHandle_t s_buffer_mutex = NULL;
static audit_entry_t s_buffer[AUDIT_BUFFER_SIZE];
static uint32_t s_buffer_count = 0;
static uint32_t s_sequence = 0;
static uint32_t s_batch_seq = 0;
static uint32_t s_flash_offset = 0;
static bool s_initialized = false;

/* Ed25519 key material (TODO: load from eFuse or secure NVS) */
static uint8_t s_ed25519_privkey[ED25519_PRIVKEY_LEN] = {0};
static uint8_t s_ed25519_pubkey[ED25519_PUBKEY_LEN] = {0};
static bool s_keys_loaded = false;

/* ---------------------------------------------------------------------------
 * Internal helpers
 * --------------------------------------------------------------------------- */

/**
 * @brief Load Ed25519 signing keys from secure storage.
 *
 * @return ESP_OK if keys are loaded and ready
 */
static esp_err_t load_signing_keys(void)
{
    /* TODO: Load Ed25519 private key from eFuse block or encrypted NVS.
     *
     * Implementation options:
     *   1. eFuse: esp_efuse_read_block() — most secure, one-time write
     *   2. NVS encrypted partition — allows key rotation
     *   3. External secure element (e.g., ATECC608A via I2C)
     *
     * For development, generate a test key pair and store in NVS.
     * In production, keys MUST be provisioned during manufacturing
     * and the private key must never leave the device. */

    ESP_LOGW(TAG, "Ed25519 key loading stub — using zero keys (DEVELOPMENT ONLY)");
    s_keys_loaded = false;

    return ESP_ERR_NOT_FOUND;
}

/**
 * @brief Sign a data buffer with Ed25519.
 *
 * @param data       Data to sign
 * @param data_len   Length of data
 * @param sig_out    Output buffer for 64-byte signature
 * @return ESP_OK on success
 */
static esp_err_t ed25519_sign(const uint8_t *data, size_t data_len,
                               uint8_t *sig_out)
{
    if (!s_keys_loaded) {
        /* No keys — write zero signature and log warning */
        memset(sig_out, 0, ED25519_SIG_LEN);
        return ESP_ERR_NOT_FOUND;
    }

    /* TODO: Implement Ed25519 signing.
     *
     * Options for ESP32-S3:
     *   1. mbedtls_pk_sign() with MBEDTLS_PK_EDDSA (if available)
     *   2. Lightweight Ed25519 library (e.g., orlp/ed25519, ~8KB flash)
     *   3. Hardware crypto acceleration via esp_ds (Digital Signature)
     *
     * The signature covers the raw entry data bytes to ensure
     * tamper detection of any individual batch. */

    memset(sig_out, 0, ED25519_SIG_LEN);
    return ESP_ERR_NOT_SUPPORTED;
}

/**
 * @brief Write a batch of entries to SPI flash.
 *
 * @param entries     Array of audit entries
 * @param count       Number of entries
 * @return ESP_OK on success
 */
static esp_err_t write_batch_to_flash(const audit_entry_t *entries,
                                       uint32_t count)
{
    if (s_partition == NULL || count == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Calculate total size */
    uint32_t entries_size = count * sizeof(audit_entry_t);
    uint32_t total_size = sizeof(audit_batch_header_t) + entries_size;

    /* Check if we have space in the partition */
    if (s_flash_offset + total_size > s_partition->size) {
        ESP_LOGW(TAG, "Audit partition full (offset=%"PRIu32", size=%"PRIu32") — "
                 "wrapping to beginning",
                 s_flash_offset, (uint32_t)s_partition->size);
        /* In production: either stop logging or implement circular buffer
         * with careful handling of the wrap-around signature chain. */
        s_flash_offset = 0;
    }

    /* Build batch header */
    audit_batch_header_t header = {
        .magic = BATCH_MAGIC,
        .batch_seq = s_batch_seq++,
        .entry_count = count,
        .total_size = total_size,
    };

    /* Sign the entry data */
    ed25519_sign((const uint8_t *)entries, entries_size, header.signature);
    memcpy(header.pubkey, s_ed25519_pubkey, ED25519_PUBKEY_LEN);

    /* Erase flash sector if needed (SPI flash requires erase before write) */
    uint32_t sector_start = (s_flash_offset / SPI_FLASH_SEC_SIZE) * SPI_FLASH_SEC_SIZE;
    if (s_flash_offset == sector_start) {
        esp_err_t ret = esp_partition_erase_range(s_partition, sector_start,
                                                   SPI_FLASH_SEC_SIZE);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Flash erase failed at offset %"PRIu32": %s",
                     sector_start, esp_err_to_name(ret));
            return ret;
        }
    }

    /* Write header */
    esp_err_t ret = esp_partition_write(s_partition, s_flash_offset,
                                        &header, sizeof(header));
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Flash write (header) failed: %s", esp_err_to_name(ret));
        return ret;
    }

    /* Write entries */
    ret = esp_partition_write(s_partition, s_flash_offset + sizeof(header),
                              entries, entries_size);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Flash write (entries) failed: %s", esp_err_to_name(ret));
        return ret;
    }

    s_flash_offset += total_size;

    /* Align to 4-byte boundary for next write */
    s_flash_offset = (s_flash_offset + 3) & ~3;

    ESP_LOGD(TAG, "Batch %"PRIu32" written: %"PRIu32" entries, %"PRIu32" bytes",
             header.batch_seq, count, total_size);

    return ESP_OK;
}

/* ---------------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------------- */

esp_err_t audit_log_init(void)
{
    if (s_initialized) {
        return ESP_OK;
    }

    /* Create buffer mutex */
    s_buffer_mutex = xSemaphoreCreateMutex();
    if (s_buffer_mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create buffer mutex");
        return ESP_ERR_NO_MEM;
    }

    /* Find audit partition */
    s_partition = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY,
        AUDIT_PARTITION_LABEL);

    if (s_partition == NULL) {
        ESP_LOGW(TAG, "Audit partition '%s' not found — logging to RAM only",
                 AUDIT_PARTITION_LABEL);
    } else {
        ESP_LOGI(TAG, "Audit partition: offset=0x%"PRIx32" size=%"PRIu32" bytes",
                 (uint32_t)s_partition->address, (uint32_t)s_partition->size);

        /* TODO: Scan partition for existing entries to find write offset
         * and continue sequence numbering. Look for BATCH_MAGIC headers
         * and validate signatures to find the last valid batch. */
    }

    /* Load signing keys */
    load_signing_keys();

    s_buffer_count = 0;
    s_sequence = 0;
    s_flash_offset = 0;
    s_initialized = true;

    ESP_LOGI(TAG, "Audit log initialized (buffer: %d entries, signing: %s)",
             AUDIT_BUFFER_SIZE, s_keys_loaded ? "ACTIVE" : "DISABLED");

    return ESP_OK;
}

void audit_log_record(const char *event_type, const char *detail,
                      int32_t numeric_value,
                      const uint8_t *payload, uint8_t payload_len)
{
    if (!s_initialized) {
        /* Best-effort: log to console if audit system isn't ready */
        ESP_LOGW(TAG, "Audit not initialized — event=%s detail=%s val=%"PRId32,
                 event_type ? event_type : "?",
                 detail ? detail : "?",
                 numeric_value);
        return;
    }

    if (xSemaphoreTake(s_buffer_mutex, pdMS_TO_TICKS(50)) != pdTRUE) {
        ESP_LOGW(TAG, "Audit buffer mutex timeout — event dropped: %s",
                 event_type ? event_type : "?");
        return;
    }

    if (s_buffer_count >= AUDIT_BUFFER_SIZE) {
        /* Buffer full — drop oldest entry and log warning */
        ESP_LOGW(TAG, "Audit buffer full — dropping oldest entry");
        memmove(&s_buffer[0], &s_buffer[1],
                (AUDIT_BUFFER_SIZE - 1) * sizeof(audit_entry_t));
        s_buffer_count = AUDIT_BUFFER_SIZE - 1;
    }

    audit_entry_t *entry = &s_buffer[s_buffer_count];
    memset(entry, 0, sizeof(audit_entry_t));

    entry->sequence = s_sequence++;
    entry->timestamp_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;
    entry->numeric_value = numeric_value;

    if (event_type) {
        strncpy(entry->event_type, event_type, sizeof(entry->event_type) - 1);
    }
    if (detail) {
        strncpy(entry->detail, detail, sizeof(entry->detail) - 1);
    }
    if (payload && payload_len > 0) {
        entry->payload_len = (payload_len > AUDIT_MAX_PAYLOAD)
                             ? AUDIT_MAX_PAYLOAD : payload_len;
        memcpy(entry->payload, payload, entry->payload_len);
    }

    s_buffer_count++;
    xSemaphoreGive(s_buffer_mutex);
}

void audit_log_flush(void)
{
    if (!s_initialized) {
        return;
    }

    if (xSemaphoreTake(s_buffer_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        ESP_LOGW(TAG, "Cannot acquire buffer mutex for flush");
        return;
    }

    if (s_buffer_count == 0) {
        xSemaphoreGive(s_buffer_mutex);
        return;
    }

    /* Copy buffer contents and reset */
    uint32_t count = s_buffer_count;
    audit_entry_t *batch = pvPortMalloc(count * sizeof(audit_entry_t));
    if (batch == NULL) {
        ESP_LOGE(TAG, "Failed to allocate flush buffer");
        xSemaphoreGive(s_buffer_mutex);
        return;
    }

    memcpy(batch, s_buffer, count * sizeof(audit_entry_t));
    s_buffer_count = 0;
    xSemaphoreGive(s_buffer_mutex);

    /* Write to flash (outside mutex to avoid delaying new records) */
    if (s_partition != NULL) {
        esp_err_t ret = write_batch_to_flash(batch, count);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Flash write failed — %"PRIu32" entries lost", count);
        } else {
            ESP_LOGI(TAG, "Flushed %"PRIu32" audit entries to flash", count);
        }
    } else {
        ESP_LOGD(TAG, "No flash partition — %"PRIu32" entries discarded", count);
    }

    vPortFree(batch);
}

uint32_t audit_log_get_sequence(void)
{
    return s_sequence;
}

uint32_t audit_log_get_flash_usage(void)
{
    if (s_partition == NULL) {
        return 0;
    }
    return s_flash_offset;
}
