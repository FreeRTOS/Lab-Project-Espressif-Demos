#
# Component Makefile
#

set (includes)
set (srcs)
set (priv_includes)

list(APPEND includes
    "source/configuration-files"
    "source/mqtt-subscription-manager"
    "source/mqtt-agent-interface/include"
    "source/logging"
    "source/network_transport"
    "source/ota_pal"
    )

list(APPEND srcs
    "source/mqtt-agent-interface/freertos_agent_message.c"
    "source/mqtt-agent-interface/freertos_command_pool.c"
    "source/mqtt-subscription-manager/mqtt_subscription_manager.c"
    "source/network_transport/tls_freertos.c"
    "source/ota_pal/ota_pal.c"
	"source/ota_pal/aws_esp_ota_ops.c"
    )

idf_component_register(SRCS "${srcs}"
                    INCLUDE_DIRS ${includes}
                    PRIV_INCLUDE_DIRS ${priv_includes}
                    REQUIRES lwip nghttp mbedtls tcp_transport)
