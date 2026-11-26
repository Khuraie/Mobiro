cmake_minimum_required(VERSION 3.22.1)
project(mobiro_runtime LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(MOBIRO_BUILD_HOST_TESTS "Build portable C++20 core unit tests on host" OFF)

# Portable core library (validator, VFS, guest arena, Box64 thunk bridge, DXVK config, input router, topology)
add_library(mobiro_core STATIC
    cpu_mem/win32_shim.cpp
)
target_include_directories(mobiro_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Optional upstream Box64 submodule integration (built from source via scripts/fetch_third_party.*)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../../../third_party/box64/CMakeLists.txt")
    target_compile_definitions(mobiro_core PUBLIC MOBIRO_HAVE_BOX64=1)
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
