cmake_minimum_required(VERSION 3.20)

project(lab1_aestool
    VERSION 1.0.0
    DESCRIPTION "Lab 1 - Symmetric Encryption with Crypto++"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(aestool
    src/main.cpp
    src/file_utils.cpp
    src/encoding.cpp
    src/aes_cbc.cpp
    src/aes_ctr.cpp
    src/aes_gcm.cpp
    src/aes_extra_modes.cpp
    src/sidecar.cpp
    src/nonce_registry.cpp
)

target_include_directories(aestool
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(aestool
    PRIVATE
        cryptopp
)

if (MSVC)
    target_compile_options(aestool PRIVATE /W4)
else()
    target_compile_options(aestool PRIVATE -Wall -Wextra -Wpedantic)
endif()

enable_testing()
