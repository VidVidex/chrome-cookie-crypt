import os
import json
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import sqlite3
import shutil
import sys
import hashlib

try:
    import win32crypt
except ImportError:
    # Not available on Linux
    pass
try:
    import keyring
except ImportError:
    # Not available on Windows
    pass


def get_key_win(path):
    with open(path, "r") as file:
        encrypted_key = json.load(file)["os_crypt"]["encrypted_key"]
    encrypted_key = base64.b64decode(encrypted_key)  # Base64 decoding
    encrypted_key = encrypted_key[5:]  # Remove 'DPAPI' from the beginning of the key
    decrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]  # Decrypt key

    return decrypted_key


def get_key_linux():
    key = keyring.get_password(f"Chromium Keys", f"Chromium Safe Storage")
    key = str.encode(key)
    return hashlib.pbkdf2_hmac("sha1", key, b"saltysalt", 1)[:16]


# https://stackoverflow.com/questions/60416350/chrome-80-how-to-decode-cookies
def decrypt_win(key, data_bytes: bytes):
    prefix = data_bytes[:3]
    nonce = data_bytes[3 : 3 + 12]
    ciphertext = data_bytes[3 + 12 : -16]
    tag = data_bytes[-16:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    decrypted_data = {
        "algorithm": "AES-GCM",
        "prefix": list(prefix),  # Convert to list to make it JSON serializable
        "nonce": list(nonce),  # Convert to list to make it JSON serializable
        "tag": list(tag),  # Convert to list to make it JSON serializable
        "plaintext": list(plaintext),  # Convert to list to make it JSON serializable
    }

    return decrypted_data


def decrypt_linux(key, data_bytes: bytes):
    prefix = data_bytes[:3]
    ciphertext = data_bytes[3:]

    iv = b" " * 16
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    plaintext = cipher.decrypt(ciphertext)

    decrypted_data = {
        "algorithm": "AES-CBC",
        "prefix": list(prefix),  # Convert to list to make it JSON serializable
        "iv": list(iv),  # Convert to list to make it JSON serializable
        "plaintext": list(plaintext),  # Convert to list to make it JSON serializable
    }

    return decrypted_data


def encrypt_win(key, data_bytes: bytes, nonce: bytes, prefix: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
    return prefix + nonce + ciphertext + tag


def encrypt_linux(key, data_bytes: bytes, iv: bytes, prefix: bytes):
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    encrypted = cipher.encrypt(data_bytes)
    return prefix + encrypted


def dump_passwords(login_data_db_path, key):

    conn = sqlite3.connect(login_data_db_path)
    cur = conn.cursor()

    # Decrypt the data and store it back in the database
    cur.execute("SELECT origin_url, username_value, password_value FROM logins")
    passwords = []
    for line in cur.fetchall():

        url, username, password = line

        if sys.platform == "win32":
            password = bytes(decrypt_win(key, password)['plaintext']).decode("utf-8")
        else:
            password = bytes(decrypt_linux(key, password)['plaintext']).decode("utf-8")

        passwords.append({"url": url, "username": username, "password": password})

    return passwords


def decrypt_database(chrome_cookies_path, decrypted_cookies_path, key):

    # Create a copy of the original file
    shutil.copyfile(chrome_cookies_path, decrypted_cookies_path)

    conn = sqlite3.connect(decrypted_cookies_path)
    cur = conn.cursor()

    # Decrypt the data and store it back in the database
    cur.execute(
        "SELECT host_key, top_frame_site_key, name, path, source_scheme, source_port, encrypted_value FROM cookies"
    )
    insert_query = "UPDATE cookies SET encrypted_value=? WHERE host_key=? AND top_frame_site_key=? AND name=? AND path=? AND source_scheme=? AND source_port=?"
    for line in cur.fetchall():

        if sys.platform == "win32":
            decrypted_data = decrypt_win(key, line[6])
        else:
            decrypted_data = decrypt_linux(key, line[6])

        cur.execute(insert_query, (json.dumps(decrypted_data), line[0], line[1], line[2], line[3], line[4], line[5]))
    conn.commit()


def encrypt_database(decrypted_cookies_path, encrypted_cookies_path, key):

    # Create a copy of the original file
    shutil.copyfile(decrypted_cookies_path, encrypted_cookies_path)

    conn = sqlite3.connect(encrypted_cookies_path)
    cur = conn.cursor()

    # Encrypt the data and store it back in the database
    cur.execute(
        "SELECT host_key, top_frame_site_key, name, path, source_scheme, source_port, encrypted_value FROM cookies"
    )
    insert_query = "UPDATE cookies SET encrypted_value=? WHERE host_key=? AND top_frame_site_key=? AND name=? AND path=? AND source_scheme=? AND source_port=?"
    for line in cur.fetchall():
        decrypted_data = json.loads(line[6])

        if sys.platform == "win32":
            encrypted_value = encrypt_win(
                key, bytes(decrypted_data["plaintext"]), bytes(decrypted_data["nonce"]), bytes(decrypted_data["prefix"])
            )
        else:
            encrypted_value = encrypt_linux(
                key, bytes(decrypted_data["plaintext"]), bytes(decrypted_data["iv"]), bytes(decrypted_data["prefix"])
            )

        cur.execute(insert_query, (encrypted_value, line[0], line[1], line[2], line[3], line[4], line[5]))
    conn.commit()


def usage():
    usage_string = """Usage:
python chrome.py decrypt <path/to/encrypted_cookies_db> <path/to/decrypted_cookies_db>
python chrome.py encrypt <path/to/decrypted_cookies_db> <path/to/encrypted_cookies_db>
python chrome.py passwords <path/to/login_data_db>
        """
    print(usage_string)


if __name__ == "__main__":

    if len(sys.argv) < 2:
        usage()
        exit(1)

    print(f"Detected platform: {sys.platform}")
    if sys.platform == "linux":
        key = get_key_linux()
    elif sys.platform == "win32":
        key_path = r"%LocalAppData%\Google\Chrome\User Data\Local State"
        key_path = os.path.expandvars(key_path)
        print(f'Using decryption key from "{key_path}"')
        key = get_key_win(key_path)
    print(f"Decryption key: {key.hex()}")

    action = sys.argv[1]

    if action == "decrypt":

        encrypted_cookies_db_path = sys.argv[2]
        decrypted_cookies_db_path = sys.argv[3]

        print(f'Using chrome cookies database at "{encrypted_cookies_db_path}"')
        print(f'Decrypted database will be stored stored at "{decrypted_cookies_db_path}"')

        decrypt_database(encrypted_cookies_db_path, decrypted_cookies_db_path, key)

        print("Decryption successful. You can copy the decrypted database to another computer and encrypt it")

    elif action == "encrypt":

        decrypted_cookies_db_path = sys.argv[2]
        encrypted_cookies_db_path = sys.argv[3]

        print(f'Using decrypted database at "{decrypted_cookies_db_path}"')
        print(f"Encrypted database will be stored stored at {encrypted_cookies_db_path}")

        encrypt_database(decrypted_cookies_db_path, encrypted_cookies_db_path, key)

        print("Encryption successful. You can copy the decrypted database to the correct location")

    elif action == "passwords":

        login_data_db_path = sys.argv[2]

        print(f'Using Login Data database at "{login_data_db_path}"')

        passwords = dump_passwords(login_data_db_path, key)

        print(f"Found {len(passwords)} passwords:")
        for password in passwords:
            print(f'URL: {password["url"]}, Username: {password["username"]}, Password: {password["password"].strip()}')

    else:
        usage()
