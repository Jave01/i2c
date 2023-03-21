cmake_minimum_required(VERSION 3.24)
project(pw_manager C)

set(CMAKE_C_STANDARD 11)

include_directories(include)

add_executable(pw_manager main.c include/main.h files.c include/files.h crypto.c crypto.h)

find_package(OpenSSL REQUIRED)
target_link_libraries(pw_manager OpenSSL::Crypto)
