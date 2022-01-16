#include "esp_log.h"

void app_esp_log_debug_write(const char *format, ...)
{
    va_list list;
    va_start(list, format);
    esp_log_writev(ESP_LOG_DEBUG, "tag", format, list);
    esp_log_write(ESP_LOG_DEBUG, "tag", "\r\n");
    va_end(list);
}

void app_esp_log_info_write(const char *format, ...)
{
    va_list list;
    va_start(list, format);
    esp_log_writev(ESP_LOG_INFO, "tag", format, list);
    esp_log_write(ESP_LOG_INFO, "tag", "\r\n");
    va_end(list);
}

void app_esp_log_warn_write(const char *format, ...)
{
    va_list list;
    va_start(list, format);
    esp_log_writev(ESP_LOG_WARN, "tag", format, list);
    esp_log_write(ESP_LOG_WARN, "tag", "\r\n");
    va_end(list);
}

void app_esp_log_error_write(const char *format, ...)
{
    va_list list;
    va_start(list, format);
    esp_log_writev(ESP_LOG_ERROR, "tag", format, list);
    esp_log_write(ESP_LOG_ERROR, "tag", "\r\n");
    va_end(list);
}
