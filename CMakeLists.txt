cmake_minimum_required(VERSION 3.14)
project(bypasscore-sdk VERSION 4.0.0 LANGUAGES CXX)

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

target_sources(bypasscore PRIVATE
    src/bypasscore.cpp
    src/binary/pe.cpp
    src/memory/region.cpp
    src/memory/scanner.cpp
    src/hook/engine.cpp
)

if(BYPASSCORE_BUILD_TESTS)
    enable_testing()
    foreach(test scanner pe hooks disasm)
        add_executable(test_${test} tests/test_${test}.cpp)
        target_link_libraries(test_${test} PRIVATE bypasscore)
        add_test(NAME test_${test} COMMAND test_${test})
    endforeach()
endif()

if(BYPASSCORE_BUILD_EXAMPLES)
    foreach(example hook_messagebox scan_pattern parse_pe)
        add_executable(${example} examples/${example}.cpp)
        target_link_libraries(${example} PRIVATE bypasscore)
    endforeach()
endif()

if(BYPASSCORE_BUILD_TOOLS)
    foreach(tool bc_dump bc_scan)
        add_executable(${tool} tools/${tool}.cpp)
        target_link_libraries(${tool} PRIVATE bypasscore)
    endforeach()
endif()

if(BYPASSCORE_BUILD_PYTHON)
    find_package(pybind11 REQUIRED)
    pybind11_add_module(pybypasscore bindings/python/pybypasscore.cpp)
    target_link_libraries(pybypasscore PRIVATE bypasscore)
endif()

# Install
install(TARGETS bypasscore
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib)
install(DIRECTORY include/bypasscore DESTINATION include)
