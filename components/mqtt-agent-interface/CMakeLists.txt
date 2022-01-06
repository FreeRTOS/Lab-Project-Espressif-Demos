idf_component_register(SRCS "source/freertos_agent_message.c"
                            "source/freertos_command_pool.c"
                       INCLUDE_DIRS "include"
                       REQUIRES coreMQTT-Agent FreeRTOS-Wrapper)
