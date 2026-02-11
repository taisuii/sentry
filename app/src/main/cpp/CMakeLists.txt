cmake_minimum_required(VERSION 3.22.1)

project("antifrida")

# Create the main library
add_library(${CMAKE_PROJECT_NAME} SHARED
    native-lib.cpp
    detector/thread_detector.cpp
    detector/memory_scanner.cpp
    detector/port_scanner.cpp
    detector/hook_detector.cpp
    detector/anti_debug.cpp
    utils/syscall_utils.cpp
)

target_link_libraries(${CMAKE_PROJECT_NAME}
    android
    log
)

# 16 KB page size alignment for Android 15+
if(ANDROID_ABI STREQUAL "arm64-v8a")
    target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,-z,max-page-size=16384")
endif()

# Add include directories
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/detector
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
)