idf_component_register(SRCS "source/aws_esp_ota_ops.c"
                            "source/ota_pal.c"
                       INCLUDE_DIRS "include"
                       REQUIRES ota spi_flash bootloader_support app_update janpatch mbedtls)
