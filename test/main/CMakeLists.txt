idf_component_register(
    SRCS "test_gcm_encryption.cpp"
    INCLUDE_DIRS "."
)

target_compile_options(${COMPONENT_LIB} PRIVATE -std=gnu++17 -Wall -Wextra -Werror)

# Workaround for ESP-IDF >= 6.0 linux target static link order where libtfpsacrypto.a
# appears after esp-idf/mbedtls/libmbedtls.a without a cyclic group.
if(IDF_VERSION_MAJOR GREATER_EQUAL 6)
    target_link_options(${COMPONENT_LIB} INTERFACE
        "-Wl,-u,esp_mbedtls_mem_calloc"
        "-Wl,-u,esp_mbedtls_mem_free"
    )
endif()
