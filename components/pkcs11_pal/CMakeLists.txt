idf_component_register(SRCS "source/core_pkcs11_pal.c"
                       REQUIRES bootloader_support spi_flash nvs_flash crypto corePKCS11)
