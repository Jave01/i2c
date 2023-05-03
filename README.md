# HSLU I2C Password Manager

Basic password manager, able to store simple key:value entries. Because of simplicity it isn't
implemented with a hash table but with the values chained one after another.

## Structure

The filestructure is as follows:

| Bytes in file     | Value                 |
| ----------------- | --------------------- |
| First 32 bytes    | SHA256 hash in binary |
| 8 bytes           | Salt                  |
| encrypted n-bytes | key1:val1\n           |
| encrypted n-bytes | key2:val2\n           |
| ...               | ...\0                 |

Whereas the hash is the master-password hash and the salt is used to encrypt/decrypt the entries with AES256.
The (plaintext) entries are newline-terminated strings chained one after another.

## Limitations

-   The application can only understand and process extended ASCII (8bit) characters.
-   Since the individual entries are arranged directly next to each other, a compromise
    must be made between write speed and file size when handling insertions.

## TODO

-   Password generation
-   Password copying to clipboard
-   maybe hash table implementation

## External Dependencies

-   [Libsodium](https://libsodium.gitbook.io/doc/)
-   [OpenSSL](https://www.openssl.org/)

### Libsodium Installation

#### Linux

```bash
sudo apt-get install libsodium-dev
```

And the src/CMakeLists.txt should like like this:

```cmake
find_package(OpenSSL REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)

add_executable(pw_manager main.c crypto.c files.c password.c)

target_include_directories(pw_manager PUBLIC include)
target_link_libraries(pw_manager ${LIBSODIUM_LIBRARIES})
include_directories(${LIBSODIUM_INCLUDE_DIRS})
target_link_libraries(pw_manager OpenSSL::Crypto)
```

#### Windows

1. Download the [libsodium-x.y.z-mingw.tar.gz](https://download.libsodium.org/libsodium/releases/) binaries and extract them to a folder of your choice.
2. Take the contents of either the x64 or x32 folder and copy them to a folder called libsodium in the root of the project.
3. Then change your src/CMakeLists.txt to the following:

```cmake
find_package(OpenSSL REQUIRED)

set(LIBSODIUM_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libsodium)
include_directories(${LIBSODIUM_DIR}/include)

add_executable(pw_manager main.c crypto.c files.c password.c)

target_include_directories(pw_manager PUBLIC include)
target_link_libraries(pw_manager PRIVATE OpenSSL::Crypto ${LIBSODIUM_DIR}/lib/libsodium.a)
```
