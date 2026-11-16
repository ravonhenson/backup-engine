cmake_minimum_required(VERSION 3.20)
project(backup_engine CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Layers, lowest first. Each may include only from layers above it in
# this list: util <- crypto <- storage <- log <- snapshot <- main.cpp.
add_library(backup_engine_core STATIC
    src/util/fs_util.cpp
    src/util/text_format.cpp

    src/crypto/digest.cpp
    src/crypto/hasher.cpp
    src/crypto/sha256_hasher.cpp
    src/crypto/merkle.cpp
    src/crypto/signing.cpp

    src/storage/object_store.cpp
    src/storage/repo.cpp

    src/log/oplog.cpp
    src/log/checkpoint.cpp

    src/snapshot/chunker.cpp
    src/snapshot/chunk_list.cpp
    src/snapshot/manifest.cpp
    src/snapshot/snapshot.cpp

    third_party/sha256/sha256.c
    third_party/monocypher/monocypher.c
    third_party/monocypher/monocypher-ed25519.c
)
# Project headers are included by path from src/ (e.g. "crypto/digest.h").
target_include_directories(backup_engine_core PUBLIC
    src
    third_party/sha256
    third_party/monocypher
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
        tests/test_manifest.cpp
        tests/test_snapshot.cpp
        tests/test_chunker.cpp
        tests/test_chunk_list.cpp
        tests/test_oplog.cpp
        tests/test_crash_safety.cpp
        tests/test_immutability.cpp
        tests/test_merkle.cpp
        tests/test_characterization.cpp
        tests/test_fs_util.cpp
        tests/test_text_format.cpp
        tests/test_ed25519.cpp
        tests/test_checkpoint.cpp
        tests/test_signing.cpp
    )
    target_link_libraries(unit_tests PRIVATE backup_engine_core GTest::gtest_main)

    include(GoogleTest)
    gtest_discover_tests(unit_tests)
endif()
