include("${CMAKE_CURRENT_LIST_DIR}/corePKCS11/pkcsFilePaths.cmake")

idf_component_register(SRCS ${PKCS_SOURCES}
                       INCLUDE_DIRS ${COREPKCS11_CONFIG_DIR}
                                    ${PKCS_INCLUDE_PUBLIC_DIRS}
                       REQUIRES pkcs11_pal mbedtls logging FreeRTOS-Wrapper)
