cmake_minimum_required(VERSION 3.1...3.29)

project( Servers VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20 -O2")

include_directories(../src)
include_directories(../extern/string_view/src)
include_directories(../../ehttp/src)
include_directories(../../misc)

add_executable(test_servers test_servers.cc)
target_link_libraries(test_servers -ludns)

