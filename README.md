# HSLU I2C Password Manager

Basic password manager, able to store simple key:value entries. Because of simplicity it isn't
implemented with a hash table but with the values chained one after another.

## Structure

The filestructure is as follows:

| Bytes in file     | Value                 |
| ----------------- | --------------------- |
| First 32 bytes    | SHA256 hash in binary |
| 8 bytes           | Salt                  |
| encrypted n-bytes | key1:val1\n\0         |
| encrypted n-bytes | key2:val2\n\0         |
| ...               | ...                   |

Whereas the hash is the masterpassword hash and the salt is used to encrypt/decrypt the entries with AES256.
The (plaintext) entries are null-terminated strings chained one after another.

## Limitations

-   The application can only understand and process extended ASCII (8bit) characters.
-   Since the individual entries are arranged directly next to each other, a compromise
    must be made between write speed and file size when handling insertions.

## TODO

-   Password generation
-   Password copying to clipboard
-   maybe hash table implementation

## External Dependencies

-   Libsodium
-   OpenSSL
