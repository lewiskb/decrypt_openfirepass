import sys
from hashlib import sha1
from Crypto.Cipher import Blowfish
from binascii import unhexlify

def decrypt_openfirepass(ciphertext, key):
    ciphertext = unhexlify(ciphertext)
    sha1_key = sha1(key.encode()).digest()
    cipher = Blowfish.new(sha1_key, Blowfish.MODE_CBC, ciphertext[:Blowfish.block_size])
    plaintext = cipher.decrypt(ciphertext[Blowfish.block_size:])
    return plaintext

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <ciphertext> <key>")
        sys.exit(1)

    ciphertext = sys.argv[1]
    key = sys.argv[2]
    print(decrypt_openfirepass(ciphertext, key).decode())
