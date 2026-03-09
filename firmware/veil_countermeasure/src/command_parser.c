/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 goop-veil contributors
 *
 * command_parser.c — UART JSON command parser.
 *
 * Receives JSON-formatted commands over UART from the host system
 * (e.g., Raspberry Pi running goop-veil Python orchestrator) and
 * dispatches them to the appropriate firmware subsystem.
 *
 * Command format (JSON over UART, newline-delimited):
 *   {"cmd": "set_channel", "channel": 6}
 *   {"cmd": "set_power", "dbm": 15}
 *   {"cmd": "get_status"}
 *   {"cmd": "clear_kill_switch"}
 *   {"cmd": "get_audit_stats"}
 *
 * Responses are JSON objects sent back over UART:
 *   {"status": "ok", "channel": 6}
 *   {"status": "error", "reason": "channel_out_of_range"}
 *
 * SAFETY: Commands that would violate safety invariants are rejected
 * with an error response. The command parser never bypasses the frame
 * filter, power limiter, or compliance monitor.
 */

#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_err.h"
#include "driver/uart.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "command_parser.h"
#include "wifi_tx.h"
#include "power_limiter.h"
#include "compliance_monitor.h"
#include "audit_log.h"
#include "frame_filter.h"
#include "legitimate_functions.h"

static const char *TAG = "cmd_parse";

/* ---------------------------------------------------------------------------
 * UART configuration
 * --------------------------------------------------------------------------- */

#define CMD_UART_NUM         UART_NUM_1
#define CMD_UART_TX_PIN      (17)
#define CMD_UART_RX_PIN      (18)
#define CMD_UART_BAUD        (115200)
#define CMD_UART_BUF_SIZE    (1024)

/* Maximum command JSON length */
#define MAX_CMD_LEN          (512)

/* ---------------------------------------------------------------------------
 * State
 * --------------------------------------------------------------------------- */

static bool s_initialized = false;
static char s_rx_buffer[MAX_CMD_LEN];
static int  s_rx_pos = 0;

/* External event group (set by main.c, passed via init or global) */
static EventGroupHandle_t s_evt_group = NULL;
static EventBits_t s_kill_bit = 0;

/* ---------------------------------------------------------------------------
 * Response helpers
 * --------------------------------------------------------------------------- */

/**
 * @brief Send a JSON response over UART.
 *
 * @param json  cJSON object to serialize and send (caller retains ownership)
 */
static void send_response(cJSON *json)
{
    if (json == NULL) return;

    char *str = cJSON_PrintUnformatted(json);
    if (str == NULL) return;

    size_t len = strlen(str);
    uart_write_bytes(CMD_UART_NUM, str, len);
    uart_write_bytes(CMD_UART_NUM, "\n", 1);

    cJSON_free(str);
}

/**
 * @brief Send a simple OK response.
 */
static void send_ok(const char *detail)
{
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "ok");
    if (detail) {
        cJSON_AddStringToObject(resp, "detail", detail);
    }
    send_response(resp);
    cJSON_Delete(resp);
}

/**
 * @brief Send an error response.
 */
static void send_error(const char *reason)
{
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "error");
    if (reason) {
        cJSON_AddStringToObject(resp, "reason", reason);
    }
    send_response(resp);
    cJSON_Delete(resp);
}

/* ---------------------------------------------------------------------------
 * Command handlers
 * --------------------------------------------------------------------------- */

/**
 * @brief Handle "set_channel" command.
 *
 * Validates channel is within 1-11 before applying.
 */
static void handle_set_channel(cJSON *root)
{
    cJSON *ch = cJSON_GetObjectItem(root, "channel");
    if (!cJSON_IsNumber(ch)) {
        send_error("missing_or_invalid_channel");
        return;
    }

    int channel = ch->valueint;
    if (channel < CHANNEL_MIN || channel > CHANNEL_MAX) {
        send_error("channel_out_of_range");
        audit_log_record("CMD_REJECTED", "channel_range", channel, NULL, 0);
        return;
    }

    esp_err_t ret = wifi_tx_set_channel((uint8_t)channel);
    if (ret == ESP_OK) {
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddStringToObject(resp, "status", "ok");
        cJSON_AddNumberToObject(resp, "channel", channel);
        send_response(resp);
        cJSON_Delete(resp);
    } else {
        send_error("channel_set_failed");
    }
}

/**
 * @brief Handle "set_power" command.
 *
 * Validates power is within limits before applying. Power NEVER adapts
 * in response to detected sensing — this is an operator-initiated change.
 */
static void handle_set_power(cJSON *root)
{
    cJSON *dbm = cJSON_GetObjectItem(root, "dbm");
    if (!cJSON_IsNumber(dbm)) {
        send_error("missing_or_invalid_dbm");
        return;
    }

    int power = dbm->valueint;
    if (power > MAX_TX_POWER_DBM) {
        send_error("power_exceeds_limit");
        audit_log_record("CMD_REJECTED", "power_limit", power, NULL, 0);
        return;
    }

    if (power < 0) {
        send_error("power_below_minimum");
        return;
    }

    esp_err_t ret = power_limiter_set_power((int8_t)power);
    if (ret == ESP_OK) {
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddStringToObject(resp, "status", "ok");
        cJSON_AddNumberToObject(resp, "power_dbm",
                                (double)power_limiter_get_current_dbm());
        send_response(resp);
        cJSON_Delete(resp);
    } else {
        send_error("power_set_failed");
    }
}

/**
 * @brief Handle "get_status" command.
 *
 * Returns current system status including power, channel, station count,
 * compliance state, and audit statistics.
 */
static void handle_get_status(void)
{
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "ok");

    /* Power */
    cJSON_AddNumberToObject(resp, "tx_power_dbm",
                            (double)power_limiter_get_current_dbm());
    cJSON_AddNumberToObject(resp, "max_power_dbm", MAX_TX_POWER_DBM);

    /* Channel */
    uint8_t primary;
    wifi_second_chan_t secondary;
    if (esp_wifi_get_channel(&primary, &secondary) == ESP_OK) {
        cJSON_AddNumberToObject(resp, "channel", primary);
    }

    /* Stations */
    cJSON_AddNumberToObject(resp, "associated_stations",
                            frame_filter_get_station_count());

    /* Compliance */
    uint32_t total_samples, total_violations;
    bool kill_latched;
    compliance_monitor_get_stats(&total_samples, &total_violations,
                                 &kill_latched);
    cJSON_AddNumberToObject(resp, "measured_power_dbm",
                            (double)compliance_monitor_get_power_dbm());
    cJSON_AddBoolToObject(resp, "kill_switch_active", kill_latched);
    cJSON_AddNumberToObject(resp, "compliance_violations", total_violations);

    /* TX stats */
    uint32_t sent, rejected;
    wifi_tx_get_stats(&sent, &rejected);
    cJSON_AddNumberToObject(resp, "frames_sent", sent);
    cJSON_AddNumberToObject(resp, "frames_rejected", rejected);

    /* Audit */
    cJSON_AddNumberToObject(resp, "audit_sequence", audit_log_get_sequence());
    cJSON_AddNumberToObject(resp, "audit_flash_bytes", audit_log_get_flash_usage());

    /* Sensors */
    float temp, hum;
    if (legitimate_functions_get_sensor_data(&temp, &hum) == ESP_OK) {
        cJSON_AddNumberToObject(resp, "temperature_c", (double)temp);
        cJSON_AddNumberToObject(resp, "humidity_pct", (double)hum);
    }

    send_response(resp);
    cJSON_Delete(resp);
}

/**
 * @brief Handle "clear_kill_switch" command.
 *
 * Attempts to clear a software-latched kill switch after verifying
 * that power is within limits and hardware switch is not active.
 */
static void handle_clear_kill_switch(void)
{
    if (s_evt_group == NULL) {
        send_error("event_group_not_set");
        return;
    }

    esp_err_t ret = compliance_monitor_clear_kill_switch(s_evt_group, s_kill_bit);
    if (ret == ESP_OK) {
        send_ok("kill_switch_cleared");
    } else if (ret == ESP_ERR_NOT_ALLOWED) {
        send_error("cannot_clear_kill_switch");
    } else {
        send_error("kill_switch_clear_failed");
    }
}

/* ---------------------------------------------------------------------------
 * Command dispatch
 * --------------------------------------------------------------------------- */

/**
 * @brief Parse and dispatch a single JSON command.
 *
 * @param json_str  Null-terminated JSON string
 */
static void dispatch_command(const char *json_str)
{
    cJSON *root = cJSON_Parse(json_str);
    if (root == NULL) {
        ESP_LOGW(TAG, "Invalid JSON: %.64s...", json_str);
        send_error("invalid_json");
        return;
    }

    cJSON *cmd = cJSON_GetObjectItem(root, "cmd");
    if (!cJSON_IsString(cmd) || cmd->valuestring == NULL) {
        send_error("missing_cmd_field");
        cJSON_Delete(root);
        return;
    }

    const char *cmd_str = cmd->valuestring;
    ESP_LOGI(TAG, "Command received: %s", cmd_str);

    if (strcmp(cmd_str, "set_channel") == 0) {
        handle_set_channel(root);
    } else if (strcmp(cmd_str, "set_power") == 0) {
        handle_set_power(root);
    } else if (strcmp(cmd_str, "get_status") == 0) {
        handle_get_status();
    } else if (strcmp(cmd_str, "clear_kill_switch") == 0) {
        handle_clear_kill_switch();
    } else if (strcmp(cmd_str, "reset_tx_stats") == 0) {
        wifi_tx_reset_stats();
        send_ok("tx_stats_reset");
    } else {
        ESP_LOGW(TAG, "Unknown command: %s", cmd_str);
        send_error("unknown_command");
    }

    cJSON_Delete(root);
}

/* ---------------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------------- */

esp_err_t command_parser_init(void)
{
    if (s_initialized) {
        return ESP_OK;
    }

    /* Configure UART */
    uart_config_t uart_cfg = {
        .baud_rate = CMD_UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    esp_err_t ret = uart_param_config(CMD_UART_NUM, &uart_cfg);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "UART config failed: %s", esp_err_to_name(ret));
        return ret;
    }

    ret = uart_set_pin(CMD_UART_NUM, CMD_UART_TX_PIN, CMD_UART_RX_PIN,
                       UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "UART pin config failed: %s", esp_err_to_name(ret));
        return ret;
    }

    ret = uart_driver_install(CMD_UART_NUM, CMD_UART_BUF_SIZE,
                              CMD_UART_BUF_SIZE, 0, NULL, 0);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "UART driver install failed: %s", esp_err_to_name(ret));
        return ret;
    }

    s_rx_pos = 0;
    s_initialized = true;

    ESP_LOGI(TAG, "Command parser initialized (UART%d, %d baud)",
             CMD_UART_NUM, CMD_UART_BAUD);

    return ESP_OK;
}

void command_parser_set_event_group(EventGroupHandle_t evt_group,
                                    EventBits_t kill_bit)
{
    s_evt_group = evt_group;
    s_kill_bit = kill_bit;
}

void command_parser_tick(void)
{
    if (!s_initialized) {
        return;
    }

    /* Read available bytes from UART */
    uint8_t byte;
    while (uart_read_bytes(CMD_UART_NUM, &byte, 1, 0) == 1) {

        if (byte == '\n' || byte == '\r') {
            if (s_rx_pos > 0) {
                s_rx_buffer[s_rx_pos] = '\0';
                dispatch_command(s_rx_buffer);
                s_rx_pos = 0;
            }
            continue;
        }

        /* Accumulate byte into buffer */
        if (s_rx_pos < MAX_CMD_LEN - 1) {
            s_rx_buffer[s_rx_pos++] = (char)byte;
        } else {
            /* Buffer overflow — discard and reset */
            ESP_LOGW(TAG, "Command buffer overflow — discarding");
            s_rx_pos = 0;
            send_error("command_too_long");
        }
    }
}
