/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 goop-veil contributors
 *
 * audit_log.h — Ed25519 signed audit trail API.
 */

#ifndef AUDIT_LOG_H
#define AUDIT_LOG_H

#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the audit log subsystem.
 *
 * Locates the SPI flash partition, loads signing keys, and prepares
 * the in-memory buffer.
 *
 * @return ESP_OK on success
 */
esp_err_t audit_log_init(void);

/**
 * @brief Record an audit event.
 *
 * Events are buffered in RAM and flushed to flash periodically
 * by audit_log_flush().
 *
 * @param event_type     Short event type string (max 15 chars)
 * @param detail         Detail string (max 15 chars, may be NULL)
 * @param numeric_value  Context-dependent numeric value
 * @param payload        Optional binary payload (may be NULL)
 * @param payload_len    Length of payload (max 32 bytes)
 */
void audit_log_record(const char *event_type, const char *detail,
                      int32_t numeric_value,
                      const uint8_t *payload, uint8_t payload_len);

/**
 * @brief Flush buffered audit events to SPI flash.
 *
 * Writes all buffered entries as a signed batch. Called periodically
 * by the audit task.
 */
void audit_log_flush(void);

/**
 * @brief Get the current audit sequence number.
 *
 * @return Monotonically increasing sequence number
 */
uint32_t audit_log_get_sequence(void);

/**
 * @brief Get the number of bytes written to flash.
 *
 * @return Flash usage in bytes, or 0 if no partition available
 */
uint32_t audit_log_get_flash_usage(void);

#ifdef __cplusplus
}
#endif

#endif /* AUDIT_LOG_H */
