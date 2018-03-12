import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generateIV():
    IV = os.urandom(16)
    return IV

def generateKey():
    key = os.urandom(32)
    return key


def Myencrypt():
    IV = generateIV()
    key = generateKey()
    if len(key) < 32:
        print("Error, length of key is less than 32")
        return 0

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    ct = encryptor.update(b"a secret message") + encryptor.finalize()
    decryptor = cipher.decryptor()
    decryptor.update(ct) + decryptor.finalize()