include("${CMAKE_CURRENT_LIST_DIR}/ota-for-aws-iot-embedded-sdk/otaFilePaths.cmake")

idf_component_register(SRCS ${TINYCBOR_SOURCES}
                            ${OTA_SOURCES}
                            ${OTA_OS_FREERTOS_SOURCES}
                            ${OTA_MQTT_SOURCES}
                       INCLUDE_DIRS ${OTA_INCLUDE_PUBLIC_DIRS}
                                    ${OTA_INCLUDE_OS_FREERTOS_DIRS}
                                    ${OTA_CONFIG_DIR}
                       PRIV_INCLUDE_DIRS ${OTA_INCLUDE_PRIVATE_DIRS}
                       REQUIRES logging FreeRTOS-Wrapper)
