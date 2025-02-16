cmake_minimum_required(VERSION 3.17)

project(runTests LANGUAGES CXX)


# disable not needed gtest options 
set(BUILD_GMOCK OFF)
set(BUILD_DOCS OFF)
set(BUILD_GTEST_TESTS OFF)
set(BUILD_GTEST_EXAMPLES OFF)

# Add the directory for googletest
add_subdirectory(googletest)

# --------- Set the C++ standard to C++20 ----------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


# --------------build unit tests and coverage ------


file(GLOB BUILD_SOURCES 
    "../lib/*.cpp"
    "../lib/*.h")

# local directory to save coverage data
#set(COVERAGE_DIRECTORY "${CMAKE_BINARY_DIR}/cov")
#file(MAKE_DIRECTORY ${COVERAGE_DIRECTORY})

# Enable coverage flags 
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fprofile-arcs -ftest-coverage")
set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fprofile-arcs -ftest-coverage")

add_executable(runTests "runTests.cpp"
                        ${BUILD_SOURCES} 
                        ${TEST_HEADERS}
                        )

target_link_libraries(runTests gtest)
target_include_directories(runTests PRIVATE googletest/include)
# --------------------------------------------------
