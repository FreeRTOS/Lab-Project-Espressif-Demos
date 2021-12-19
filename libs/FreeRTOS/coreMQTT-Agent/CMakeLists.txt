include("${CMAKE_CURRENT_LIST_DIR}/coreMQTT-Agent/mqttAgentFilePaths.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/coreMQTT-Agent/source/dependency/coreMQTT/mqttFilePaths.cmake")

idf_component_register(SRCS ${MQTT_SOURCES}
                            ${MQTT_SERIALIZER_SOURCES}
                            ${MQTT_AGENT_SOURCES}
                       INCLUDE_DIRS ${MQTT_CONFIG_DIR}
                                    ${MQTT_INCLUDE_PUBLIC_DIRS}
                                    ${MQTT_AGENT_INCLUDE_PUBLIC_DIRS}
                       REQUIRES logging)
