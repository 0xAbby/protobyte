cmake_minimum_required(VERSION 3.17)

project(protobyte LANGUAGES CXX)
project(runTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

enable_testing()

add_subdirectory(googletest)

file(GLOB TEST_HEADERS
    "src/include")

file(GLOB BUILD_SOURCES 
    "src/lib/*.cpp"
    "src/lib/*.h")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}) 

add_executable(protobyte "src/main.cpp" 
                        ${BUILD_SOURCES})


add_executable(runTests "src/runTests.cpp"
                        ${BUILD_SOURCES} 
                        ${TEST_HEADERS})

target_link_libraries(runTests gtest gtest_main)
target_include_directories(runTests PRIVATE googletest/include)

#target_link_libraries(runTests GTest::GTest GTest::Main)
