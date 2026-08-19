cmake_minimum_required(VERSION 3.10)
project(BanDrop CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
add_compile_options(-Wall -Wextra)

find_package(OpenSSL REQUIRED)

add_executable(bandrop main.cpp)
target_link_libraries(bandrop OpenSSL::SSL OpenSSL::Crypto)

enable_testing()
add_executable(selftest tests/selftest.cpp)
target_link_libraries(selftest OpenSSL::SSL OpenSSL::Crypto)
add_test(NAME selftest COMMAND selftest)
