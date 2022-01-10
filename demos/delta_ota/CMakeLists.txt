# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.5)

# Variables used in our components.
set(OTA_CONFIG_DIR ${CMAKE_CURRENT_LIST_DIR}/config)
set(MQTT_CONFIG_DIR ${CMAKE_CURRENT_LIST_DIR}/config)
set(COREPKCS11_CONFIG_DIR ${CMAKE_CURRENT_LIST_DIR}/config)
set(MBEDTLS_CONFIG_DIR ${CMAKE_CURRENT_LIST_DIR}/config)

set(EXTRA_COMPONENT_DIRS $ENV{IDF_PATH}/examples/common_components/protocol_examples_common
                         ../../components/crypto
                         ../../components/FreeRTOS-Wrapper
                         ../../components/logging
                         ../../components/mqtt-agent-interface
                         ../../components/mqtt-subscription-manager
                         ../../components/network_transport
                         ../../components/ota_pal
                         ../../components/pkcs11_helpers
                         ../../components/pkcs11_pal
                         ../../libs/AWS/ota
                         ../../libs/FreeRTOS/backoffAlgorithm
                         ../../libs/FreeRTOS/coreMQTT-Agent
                         ../../libs/FreeRTOS/corePKCS11
                         ../../libs/ThirdParty/janpatch)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(delta-ota)

# Enable the "threading_alt.h" to the mbedTLS in the ESP-IDF.
idf_build_set_property(INCLUDE_DIRECTORIES ${MBEDTLS_CONFIG_DIR} APPEND)

#target_add_binary_data(${CMAKE_PROJECT_NAME}.elf "main/root_cert_auth.pem" TEXT)
#target_add_binary_data(${CMAKE_PROJECT_NAME}.elf "main/client.crt" TEXT)
#target_add_binary_data(${CMAKE_PROJECT_NAME}.elf "main/client.key" TEXT)
