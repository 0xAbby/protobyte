cmake_minimum_required(VERSION 3.17)

# --------- Set the C++ standard to C++20 ----------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


# --------------build unit tests and coverage ------
file(GLOB BUILD_SOURCES 
    "../lib/*.cpp"
    "../lib/*.h")


project(runTests LANGUAGES CXX)
#file(GLOB TEST_HEADERS
#    "src/include")

enable_testing()

# local directory to save coverage data
set(COVERAGE_DIRECTORY "${CMAKE_BINARY_DIR}/cov")
file(MAKE_DIRECTORY ${COVERAGE_DIRECTORY})

# Enable coverage flags 
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fprofile-arcs -ftest-coverage")
set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fprofile-arcs -ftest-coverage")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-dir=./cov/")

# Add the directory for googletest
add_subdirectory(googletest)
add_executable(runTests "runTests.cpp"
                        ${BUILD_SOURCES} 
                        ${TEST_HEADERS})

target_link_libraries(runTests gtest gtest_main)
target_include_directories(runTests PRIVATE googletest/include)

# --------------------------------------------------
