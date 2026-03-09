/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 goop-veil contributors
 *
 * command_parser.h — UART JSON command parser API.
 */

#ifndef COMMAND_PARSER_H
#define COMMAND_PARSER_H

#include <stdint.h>
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the UART command parser.
 *
 * Configures UART peripheral and installs driver.
 *
 * @return ESP_OK on success
 */
esp_err_t command_parser_init(void);

/**
 * @brief Set the event group for kill switch control.
 *
 * Must be called after init so the command parser can clear
 * the kill switch when commanded.
 *
 * @param evt_group  FreeRTOS event group handle
 * @param kill_bit   Event bit for kill switch
 */
void command_parser_set_event_group(EventGroupHandle_t evt_group,
                                    EventBits_t kill_bit);

/**
 * @brief Execute one tick of command parsing.
 *
 * Reads available UART bytes, accumulates into a line buffer,
 * and dispatches complete JSON commands.
 */
void command_parser_tick(void);

#ifdef __cplusplus
}
#endif

#endif /* COMMAND_PARSER_H */
