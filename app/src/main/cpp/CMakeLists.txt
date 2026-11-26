cmake_minimum_required(VERSION 3.22.1)
project(mobiro_runtime LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(MOBIRO_BUILD_HOST_TESTS "Build portable C++20 core unit tests on host" OFF)

# Portable core library (validator, VFS, guest arena, Box64 thunk bridge, DXVK config, input router, topology)
add_library(mobiro_core STATIC
    cpu_mem/win32_shim.cpp
)
target_include_directories(mobiro_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Optional upstream Box64 prebuilt static library integration (built via scripts/build_box64_android.sh)
set(MOBIRO_BOX64_PREBUILT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../third_party/prebuilt/arm64-v8a/box64")
if(ANDROID AND EXISTS "${MOBIRO_BOX64_PREBUILT}/include/emu/x64emu_private.h")
    file(GLOB MOBIRO_BOX64_LIBS "${MOBIRO_BOX64_PREBUILT}/lib/libbox64*.a")
    if(MOBIRO_BOX64_LIBS)
        target_sources(mobiro_core PRIVATE cpu_mem/box64_c_shim.c)
        set_source_files_properties(cpu_mem/box64_c_shim.c PROPERTIES
            COMPILE_DEFINITIONS "ARM64=1;DYNAREC=1;ANDROID=1"
        )
        target_compile_definitions(mobiro_core PUBLIC MOBIRO_HAVE_BOX64=1)
        target_include_directories(mobiro_core PRIVATE "${MOBIRO_BOX64_PREBUILT}/include")
        target_link_libraries(mobiro_core PUBLIC ${MOBIRO_BOX64_LIBS} m)
    endif()
endif()

if(ANDROID)
    find_package(game-activity REQUIRED CONFIG)
    find_package(games-frame-pacing REQUIRED CONFIG)

    add_library(mobiro_runtime SHARED
        runtime_main.cpp
    )
    set_target_properties(mobiro_runtime PROPERTIES OUTPUT_NAME "sekiro_runtime")

    target_link_libraries(mobiro_runtime
        PRIVATE
            mobiro_core
            game-activity::game-activity_static
            games-frame-pacing::swappy_static
            aaudio
            android
            log
            dl
    )
endif()

if(MOBIRO_BUILD_HOST_TESTS)
    enable_testing()
    add_executable(mobiro_core_tests
        ../../../../tests/test_core.cpp
    )
    target_link_libraries(mobiro_core_tests PRIVATE mobiro_core)
    add_test(NAME mobiro_core_tests COMMAND mobiro_core_tests)
endif()
