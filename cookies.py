import os
import json
import base64 
import win32crypt
from Crypto.Cipher import AES
import sqlite3
import shutil
import sys


def get_key(path):
    with open(path, 'r') as file:
        encrypted_key = json.load(file)['os_crypt']['encrypted_key']
    encrypted_key = base64.b64decode(encrypted_key)                                       # Base64 decoding
    encrypted_key = encrypted_key[5:]                                                     # Remove 'DPAPI' from the beginning of the key
    decrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]  # Decrypt key

    return decrypted_key

# https://stackoverflow.com/questions/60416350/chrome-80-how-to-decode-cookies
def decrypt(key, data_bytes: bytes):
    nonce = data_bytes[3:3+12]
    ciphertext = data_bytes[3+12:-16]
    tag = data_bytes[-16:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext, nonce

def encrypt( key, data_bytes: bytes, nonce: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
    return  b'v10' + nonce + ciphertext + tag


def decrypt_database(chrome_cookies_path, decrypted_cookies_path, key):

    # Create a copy of the original file
    shutil.copyfile(chrome_cookies_path, decrypted_cookies_path)
    
    conn = sqlite3.connect(decrypted_cookies_path)
    cur = conn.cursor()

    # Decrypt the data and store it back in the database
    cur.execute("SELECT host_key, top_frame_site_key, name, path, source_scheme, source_port, encrypted_value FROM cookies")
    insert_query = 'UPDATE cookies SET encrypted_value=? WHERE host_key=? AND top_frame_site_key=? AND name=? AND path=? AND source_scheme=? AND source_port=?'
    for line in cur.fetchall():
        decrypted_value, nonce = decrypt(key, line[6])
        # Store nonce and data together
        cur.execute(insert_query, (nonce+decrypted_value, line[0], line[1], line[2], line[3], line[4], line[5]))
    conn.commit()

def encrypt_database(decrypted_cookies_path, encrypted_cookies_path, key):

    # Create a copy of the original file
    shutil.copyfile(decrypted_cookies_path, encrypted_cookies_path)

    conn = sqlite3.connect(encrypted_cookies_path)
    cur = conn.cursor()

    # Encrypt the data and store it back in the database
    cur.execute("SELECT host_key, top_frame_site_key, name, path, source_scheme, source_port, encrypted_value FROM cookies")
    insert_query = 'UPDATE cookies SET encrypted_value=? WHERE host_key=? AND top_frame_site_key=? AND name=? AND path=? AND source_scheme=? AND source_port=?'
    for line in cur.fetchall():
        # First 12 bytes are nonce, the rest is data
        nonce = line[6][:12]
        decrypted_value = line[6][12:]
        encrypted_value = encrypt(key, decrypted_value, nonce)
        cur.execute(insert_query, (encrypted_value, line[0], line[1], line[2], line[3], line[4], line[5]))
    conn.commit()


if __name__ == '__main__':

    if len(sys.argv) < 2:
        print('Usage: python cookies.py decrypt|encrypt')
        exit(1)

    key_path  = r'%LocalAppData%\Google\Chrome\User Data\Local State'
    key_path = os.path.expandvars(key_path)
    print(f'Using decryption key from "{key_path}"')
    
    key = get_key(key_path)
    print(f'Decryption key: {''.join('{:02x}'.format(x) for x in key)}')

    chome_cookies_path = r'%LocalAppData%\Google\Chrome\User Data\Profile 1\Network\Cookies'
    chome_cookies_path = os.path.expandvars(chome_cookies_path)
    decrypted_cookies_path = 'cookies.sqlite'
    encrypted_cookies_path = 'Cookies'

    action = sys.argv[1]

    if action == 'decrypt':

        print(f'Using chrome cookies database at "{chome_cookies_path}"')
        print(f'Decrypted database will be stored stored at "{decrypted_cookies_path}"')

        decrypt_database(chome_cookies_path, decrypted_cookies_path, key)
        
        print('Decryption successful. You can copy the decrypted database to another computer and encrypt it')

    elif action == 'encrypt':
       
        print(f'Using decrypted database at "{decrypted_cookies_path}"')
        print(f'Encrypted database will be stored stored at {encrypted_cookies_path}')

        encrypt_database(decrypted_cookies_path, encrypted_cookies_path, key)

        print('Encryption successful. You can copy the decrypted database to the correct location')
