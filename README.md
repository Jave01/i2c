# HSLU I2C Password Manager

Basic password manager, able to store simple key:value entries. Because of simplicity it isn't 
implemented with a hash table but with the values chained one after another.

## Structure

The Structure of the file is as follows:

| Bytes in file         | Value                                 |
|-----------------------|---------------------------------------|
| First 32 bytes        | SHA256 hash of master password in hex |
| strlen(val1+key1) + 3 | key1:val1\n\0                         |
| strlen(val2+key2) + 3 | key2:val2\n\0                         |
| ...                   | ...                                   |       

## Limitations

- The application can only understand and process extended ASCII (8bit) characters.
- Since the individual entries are arranged directly next to each other, a compromise 
must be made between write speed and file size when handling insertions.

## TODO

- AES256 file encryption
- Password generation
- Password copying to clipboard
- Secure salt generation

## External Dependencies

- Libsodium
- OpenSSL