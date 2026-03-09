/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 goop-veil contributors
 *
 * main.c — Main entry point for the goop-veil countermeasure firmware.
 *
 * Initializes NVS, WiFi, GPIO, ADC, and spawns FreeRTOS tasks for:
 *   - RF environment management (TX task)
 *   - Compliance monitoring (ADC power measurement + kill switch)
 *   - Audit logging (signed event trail)
 *   - UART command parsing
 *   - Legitimate functions (mesh AP, sensors, FTM)
 *
 * SAFETY: This firmware enforces strict RF compliance at multiple layers.
 * See frame_filter.c and power_limiter.c for critical safety checks.
 */

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_err.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include "driver/adc.h"
#include "esp_adc/adc_oneshot.h"

/* Project headers */
#include "wifi_tx.h"
#include "frame_filter.h"
#include "compliance_monitor.h"
#include "power_limiter.h"
#include "legitimate_functions.h"
#include "audit_log.h"
#include "command_parser.h"

static const char *TAG = "veil_main";

/* ---------------------------------------------------------------------------
 * FreeRTOS task configuration
 * --------------------------------------------------------------------------- */
#define TASK_STACK_SIZE_TX          (4096)
#define TASK_STACK_SIZE_COMPLIANCE  (4096)
#define TASK_STACK_SIZE_AUDIT       (4096)
#define TASK_STACK_SIZE_COMMAND     (4096)
#define TASK_STACK_SIZE_LEGIT       (4096)

#define TASK_PRIORITY_TX           (5)
#define TASK_PRIORITY_COMPLIANCE   (configMAX_PRIORITIES - 1)  /* Highest — safety critical */
#define TASK_PRIORITY_AUDIT        (3)
#define TASK_PRIORITY_COMMAND      (4)
#define TASK_PRIORITY_LEGIT        (2)

/* Kill-switch GPIO (active-low: pull LOW to disable all TX) */
#define GPIO_KILL_SWITCH           (GPIO_NUM_4)

/* Event group bits */
#define EVT_WIFI_READY             (1 << 0)
#define EVT_KILL_SWITCH_ACTIVE     (1 << 1)

static EventGroupHandle_t s_evt_group;
static SemaphoreHandle_t  s_tx_mutex;

/* ---------------------------------------------------------------------------
 * WiFi event handler
 * --------------------------------------------------------------------------- */
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT) {
        switch (event_id) {
        case WIFI_EVENT_AP_START:
            ESP_LOGI(TAG, "SoftAP started");
            xEventGroupSetBits(s_evt_group, EVT_WIFI_READY);
            break;
        case WIFI_EVENT_AP_STOP:
            ESP_LOGW(TAG, "SoftAP stopped");
            xEventGroupClearBits(s_evt_group, EVT_WIFI_READY);
            break;
        case WIFI_EVENT_AP_STACONNECTED: {
            wifi_event_ap_staconnected_t *evt = (wifi_event_ap_staconnected_t *)event_data;
            ESP_LOGI(TAG, "Station " MACSTR " connected, AID=%d",
                     MAC2STR(evt->mac), evt->aid);
            break;
        }
        case WIFI_EVENT_AP_STADISCONNECTED: {
            wifi_event_ap_stadisconnected_t *evt = (wifi_event_ap_stadisconnected_t *)event_data;
            ESP_LOGI(TAG, "Station " MACSTR " disconnected, AID=%d",
                     MAC2STR(evt->mac), evt->aid);
            break;
        }
        default:
            break;
        }
    }
}

/* ---------------------------------------------------------------------------
 * Hardware initialization
 * --------------------------------------------------------------------------- */

/**
 * @brief Initialize NVS flash (required for WiFi).
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
 * @brief Initialize WiFi in AP mode with WPA3.
 *
 * The AP serves as the device's own BSS for legitimate mesh networking.
 * Frame filter will only allow management frames addressed to this BSS.
 */
static esp_err_t init_wifi(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));

    /* Configure AP — channel and SSID set by legitimate_functions */
    wifi_config_t wifi_config = {
        .ap = {
            .ssid = "VEIL-MESH",
            .ssid_len = 9,
            .channel = 1,
            .authmode = WIFI_AUTH_WPA3_PSK,
            .max_connection = 4,
            .pmf_cfg = {
                .required = true,
            },
        },
    };

    /* PSK is set from NVS or command interface, not hardcoded */
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));

    /* Enforce initial power limit */
    ESP_ERROR_CHECK(power_limiter_init());

    ESP_ERROR_CHECK(esp_wifi_start());

    return ESP_OK;
}

/**
 * @brief Initialize kill-switch GPIO.
 *
 * Active-low input with internal pull-up. When pulled LOW (e.g., by a
 * physical toggle or compliance monitor), all TX is immediately halted.
 */
static esp_err_t init_kill_switch_gpio(void)
{
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << GPIO_KILL_SWITCH),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_NEGEDGE,
    };
    return gpio_config(&io_conf);
}

/* ---------------------------------------------------------------------------
 * FreeRTOS task functions
 * --------------------------------------------------------------------------- */

/**
 * @brief TX management task.
 *
 * Dequeues frames from the command pipeline, validates them through the
 * frame filter, and transmits if compliant.
 */
static void tx_task(void *pvParameters)
{
    ESP_LOGI(TAG, "TX task started");

    /* Wait for WiFi to be ready */
    xEventGroupWaitBits(s_evt_group, EVT_WIFI_READY,
                        pdFALSE, pdTRUE, portMAX_DELAY);

    while (1) {
        /* Check kill switch */
        EventBits_t bits = xEventGroupGetBits(s_evt_group);
        if (bits & EVT_KILL_SWITCH_ACTIVE) {
            ESP_LOGW(TAG, "Kill switch active — TX suspended");
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        /* TODO: Dequeue frame from command pipeline */
        /* TODO: Call wifi_tx_send_frame() which internally calls frame_filter */

        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

/**
 * @brief Compliance monitoring task (highest priority).
 *
 * Continuously reads ADC power measurement and asserts kill switch
 * if conducted power exceeds MAX_TX_POWER_DBM.
 */
static void compliance_task(void *pvParameters)
{
    ESP_LOGI(TAG, "Compliance monitor task started (priority: HIGHEST)");

    while (1) {
        compliance_monitor_tick(s_evt_group, EVT_KILL_SWITCH_ACTIVE);
        vTaskDelay(pdMS_TO_TICKS(5));  /* 200 Hz sampling */
    }
}

/**
 * @brief Audit log flush task.
 *
 * Periodically flushes buffered audit events to SPI flash with
 * Ed25519 signatures.
 */
static void audit_task(void *pvParameters)
{
    ESP_LOGI(TAG, "Audit log task started");

    while (1) {
        audit_log_flush();
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

/**
 * @brief UART command parser task.
 *
 * Reads JSON commands from UART and dispatches them to the appropriate
 * subsystem after validation.
 */
static void command_task(void *pvParameters)
{
    ESP_LOGI(TAG, "Command parser task started");

    while (1) {
        command_parser_tick();
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

/**
 * @brief Legitimate functions task.
 *
 * Manages mesh AP beaconing, environmental sensors, and FTM ranging.
 */
static void legit_task(void *pvParameters)
{
    ESP_LOGI(TAG, "Legitimate functions task started");

    /* Wait for WiFi */
    xEventGroupWaitBits(s_evt_group, EVT_WIFI_READY,
                        pdFALSE, pdTRUE, portMAX_DELAY);

    while (1) {
        legitimate_functions_tick();
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

/* ---------------------------------------------------------------------------
 * Application entry point
 * --------------------------------------------------------------------------- */
void app_main(void)
{
    ESP_LOGI(TAG, "=== goop-veil countermeasure firmware ===");
    ESP_LOGI(TAG, "Build: %s %s", __DATE__, __TIME__);

    /* Create synchronization primitives */
    s_evt_group = xEventGroupCreate();
    s_tx_mutex = xSemaphoreCreateMutex();
    configASSERT(s_evt_group != NULL);
    configASSERT(s_tx_mutex != NULL);

    /* Hardware initialization sequence */
    ESP_ERROR_CHECK(init_nvs());
    ESP_LOGI(TAG, "NVS initialized");

    ESP_ERROR_CHECK(init_kill_switch_gpio());
    ESP_LOGI(TAG, "Kill switch GPIO initialized");

    ESP_ERROR_CHECK(frame_filter_init());
    ESP_LOGI(TAG, "Frame filter initialized (safety checks active)");

    ESP_ERROR_CHECK(compliance_monitor_init());
    ESP_LOGI(TAG, "Compliance monitor initialized");

    ESP_ERROR_CHECK(audit_log_init());
    ESP_LOGI(TAG, "Audit log initialized");

    ESP_ERROR_CHECK(command_parser_init());
    ESP_LOGI(TAG, "Command parser initialized");

    ESP_ERROR_CHECK(legitimate_functions_init());
    ESP_LOGI(TAG, "Legitimate functions initialized");

    ESP_ERROR_CHECK(init_wifi());
    ESP_LOGI(TAG, "WiFi AP initialized");

    /* Spawn FreeRTOS tasks */
    /* SAFETY: Compliance task runs at highest priority to ensure kill switch
     * can always preempt TX operations. */
    xTaskCreate(compliance_task, "compliance", TASK_STACK_SIZE_COMPLIANCE,
                NULL, TASK_PRIORITY_COMPLIANCE, NULL);

    xTaskCreate(tx_task, "tx_mgmt", TASK_STACK_SIZE_TX,
                NULL, TASK_PRIORITY_TX, NULL);

    xTaskCreate(audit_task, "audit", TASK_STACK_SIZE_AUDIT,
                NULL, TASK_PRIORITY_AUDIT, NULL);

    xTaskCreate(command_task, "cmd_parse", TASK_STACK_SIZE_COMMAND,
                NULL, TASK_PRIORITY_COMMAND, NULL);

    xTaskCreate(legit_task, "legit_fn", TASK_STACK_SIZE_LEGIT,
                NULL, TASK_PRIORITY_LEGIT, NULL);

    ESP_LOGI(TAG, "All tasks started. System operational.");
}
