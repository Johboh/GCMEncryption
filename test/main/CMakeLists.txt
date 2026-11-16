idf_component_register(
    SRCS "test_gcm_encryption.cpp"
    INCLUDE_DIRS "."
)

target_compile_options(${COMPONENT_LIB} PRIVATE -std=gnu++17 -Wall -Wextra -Werror)
