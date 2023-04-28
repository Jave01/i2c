find_package(OpenSSL REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)

add_executable(pw_manager main.c crypto.c files.c password.c)

target_include_directories(pw_manager PUBLIC include)
target_link_libraries(pw_manager ${LIBSODIUM_LIBRARIES})
include_directories(${LIBSODIUM_INCLUDE_DIRS})
target_link_libraries(pw_manager OpenSSL::Crypto)