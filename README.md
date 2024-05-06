# Chrome Cookie Database Encryption/Decryption

This is a simple Python script that can be used to encrypt and decrypt the Chrome cookie database.

## Why

This script can be used to quickly and easily transfer cookies between computers, allowing you to use existing sessions on a new device.

On Windows, the Chrome cookie database is encrypted using the Windows Data Protection API, which means you cannot simply copy the database to a new computer.
This script can decrypt cookies in the database, allowing you to copy the decrypted database to a new computer and encrypt it there.
Decryption and encryption are done on different computers, because this way we do not need to know DPAPI keys.
For encryption Chrome generates a key, which is used to encrypt the cookies and encrypts it with DPAPI before storing it in a file called `Local State`.

On Linux the encryption key is stored in the system keyring.
This script currently only supports KDE Wallet.

## Usage

Decrypt the cookies database:

```sh
python cookies.py decrypt <path/to/encrypted_cookies_db> <path/to/decrypted_cookies_db>
```

Encrypt the cookies database:

```sh
python cookies.py encrypt <path/to/decrypted_cookies_db> <path/to/encrypted_cookies_db>
```

## File locations

### Windows

- `Local State` file: `%LOCALAPPDATA%\Google\Chrome\User Data\Local State`
- Cookies database: `%LOCALAPPDATA%\Google\Chrome\User Data\<profile name>\Cookies`, where profile name is `Default`, `Profile 1`, etc.

### Linux (chromium)

- cookies database: `~/.config/chromium/<profile name>/Cookies` where profile name is `Default`, `Profile 1`, etc.
