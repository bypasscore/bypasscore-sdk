cmake_minimum_required(VERSION 3.14)
project(bypasscore-sdk VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BYPASSCORE_BUILD_TESTS "Build unit tests" ON)
option(BYPASSCORE_BUILD_EXAMPLES "Build examples" ON)
option(BYPASSCORE_BUILD_TOOLS "Build tools" ON)
option(BYPASSCORE_BUILD_PYTHON "Build Python bindings" OFF)

add_library(bypasscore STATIC)

target_include_directories(bypasscore PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_definitions(bypasscore PRIVATE
    BYPASSCORE_BUILDING
    _CRT_SECURE_NO_WARNINGS
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

if(MSVC)
    target_compile_options(bypasscore PRIVATE /W4 /permissive-)
else()
    target_compile_options(bypasscore PRIVATE -Wall -Wextra -Wpedantic)
endif()
