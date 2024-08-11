cmake_minimum_required(VERSION 3.1...3.29)

project(
  Servers
  VERSION 1.0
  LANGUAGES CXX)

add_subdirectory(extern/string_view)
add_subdirectory(tests)

# relies on libudns, probably a cmake cmd to install as needed
# sudo apt install libudns-dev
