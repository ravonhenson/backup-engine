cmake_minimum_required(VERSION 3.20)
project(backup_engine CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(backup_engine_core STATIC
    third_party/sha256/sha256.c
    src/digest.cpp
    src/hasher.cpp
    src/sha256_hasher.cpp
    src/object_store.cpp
    src/repo.cpp
)
target_include_directories(backup_engine_core PUBLIC
    src
    third_party/sha256
)

add_executable(backup_engine src/main.cpp)
target_link_libraries(backup_engine PRIVATE backup_engine_core)

option(BACKUP_ENGINE_BUILD_TESTS "Build the unit test suite" ON)
if(BACKUP_ENGINE_BUILD_TESTS)
    include(FetchContent)
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.zip
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    enable_testing()

    add_executable(unit_tests
        tests/test_digest.cpp
        tests/test_object_store.cpp
    )
    target_link_libraries(unit_tests PRIVATE backup_engine_core GTest::gtest_main)

    include(GoogleTest)
    gtest_discover_tests(unit_tests)
endif()
