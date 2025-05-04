FILE(GLOB_RECURSE sources "./src/impl/*.*")

set(required_components mbedtls)

idf_component_register(COMPONENT_NAME "gcmencryption"
                        SRCS ${sources}
                        INCLUDE_DIRS "./src/"
                        REQUIRES ${required_components})


if(IDF_VERSION_MAJOR LESS 5) # 5+ compiles with c++23.
target_compile_options(${COMPONENT_LIB} PRIVATE -std=gnu++17)
endif()
