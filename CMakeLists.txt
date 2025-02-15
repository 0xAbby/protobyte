cmake_minimum_required(VERSION 3.17)

project(protobyte LANGUAGES CXX)

# --------- Set the C++ standard to C++20 ----------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s")

# ------------- build stand-alone binary -----------

file(GLOB BUILD_SOURCES 
    "src/lib/*.cpp"
    "src/lib/*.h")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}) 

add_executable(protobyte "src/main.cpp" 
                        ${BUILD_SOURCES})


# --------------------------------------------------
