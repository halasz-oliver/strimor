cmake_minimum_required(VERSION 3.10)
project(strimor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Try to find libsodium via pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM libsodium)

# Determine include and library paths
if (SODIUM_FOUND)
    message(STATUS "Found libsodium via pkg-config")
    set(SODIUM_INCLUDE_DIR ${SODIUM_INCLUDE_DIRS})
    find_library(SODIUM_LIB_PATH sodium HINTS ${SODIUM_LIBRARY_DIRS} PATH_SUFFIXES lib)
else()
    message(STATUS "Using Homebrew libsodium fallback")
    set(SODIUM_INCLUDE_DIR /opt/homebrew/include)
    set(SODIUM_LIB_PATH /opt/homebrew/lib/libsodium.dylib)
endif()

message(STATUS "libsodium include: ${SODIUM_INCLUDE_DIR}")
message(STATUS "libsodium library: ${SODIUM_LIB_PATH}")

# Example executable
add_executable(strimor_example example.cpp)
target_include_directories(strimor_example PRIVATE ${SODIUM_INCLUDE_DIR})
target_link_libraries(strimor_example PRIVATE ${SODIUM_LIB_PATH})

# Benchmark executable
add_executable(strimor_benchmark benchmark.cpp)
target_include_directories(strimor_benchmark PRIVATE ${SODIUM_INCLUDE_DIR})
target_link_libraries(strimor_benchmark PRIVATE ${SODIUM_LIB_PATH})