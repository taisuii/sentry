cmake_minimum_required(VERSION 3.22.1)

project("antidebug")

# Create the main library
add_library(${CMAKE_PROJECT_NAME} SHARED
    native-lib.cpp
    detector/thread_detector.cpp
    detector/memory_scanner.cpp
    detector/port_scanner.cpp
    detector/hook_detector.cpp
    detector/so_integrity.cpp
    detector/art_method_detector.cpp
    detector/trap_detector.cpp
    detector/xposed_detector.cpp
    detector/class_linker_scan.cpp
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

# ========== libenvdetect (环境检测 Native 库) ==========
# 预期签名 SHA256（64 位十六进制）由 Gradle 在 release 构建时传入，Debug 为空则跳过校验
if(NOT DEFINED EXPECTED_SIGNATURE_SHA256)
    set(EXPECTED_SIGNATURE_SHA256 "")
endif()
add_library(envdetect SHARED
    native-lib-env.cpp
    detector/env_detector.cpp
    detector/signature_checker.cpp
    detector/apk_signature.cpp
    utils/syscall_utils.cpp
)
target_include_directories(envdetect PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/detector
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
)
target_compile_definitions(envdetect PRIVATE EXPECTED_SIGNATURE_SHA256="${EXPECTED_SIGNATURE_SHA256}")
target_link_libraries(envdetect
    android
    log
)
if(ANDROID_ABI STREQUAL "arm64-v8a")
    target_link_options(envdetect PRIVATE "-Wl,-z,max-page-size=16384")
endif()
