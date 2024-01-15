cmake_minimum_required(VERSION 3.17)

project(binlyzer LANGUAGES CXX)
project(runTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

enable_testing()
find_package(GTest REQUIRED)

include_directories(gtest/include)
file(GLOB_RECURSE google_test_headers /usr/include/gtest/*.h)

file(GLOB TEST_HEADERS
    "src/include")

file(GLOB BUILD_SOURCES 
    "src/lib/*.cpp"
    "src/lib/*.h")

add_executable(binlyzer "src/main.cpp" 
                        ${BUILD_SOURCES})


add_executable(runTests "src/runTests.cpp"
                        ${BUILD_SOURCES} 
                        ${TEST_HEADERS})

target_link_libraries(runTests GTest::GTest GTest::Main)
