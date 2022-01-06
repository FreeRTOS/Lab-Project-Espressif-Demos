idf_component_register(SRCS "source/tls_freertos.c"
                       INCLUDE_DIRS "include"
                       REQUIRES logging tcp_transport coreMQTT-Agent FreeRTOS-Wrapper)
