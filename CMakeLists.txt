cmake_minimum_required(VERSION 3.24)
project(pw_manager C)

set(CMAKE_C_STANDARD 11)

include_directories(include)
include_directories(/usr/local/include)
include_directories(libsodium-stable/src/libsodium/include)

add_executable(pw_manager main.c include/main.h files.c include/files.h crypto.c include/crypto.h password.c include/password.h)

find_package(OpenSSL REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(libsodium REQUIRED)

include_directories(${LIBSODIUM_INCLUDE_DIRS})
link_directories(${LIBSODIUM_LIBRARY_DIRS})


target_link_libraries(pw_manager ${LIBSODIUM_LIBRARIES})
target_link_libraries(pw_manager OpenSSL::Crypto)
