cmake_minimum_required(VERSION 3.10)
project(BanDrop CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

find_package(OpenSSL REQUIRED)

add_executable(bandrop main.cpp)
target_link_libraries(bandrop OpenSSL::SSL OpenSSL::Crypto)
