import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generateIV():
    IV = os.urandom(16)
    fileName = "IV.txt"
    myFile = open(fileName, 'w')
    myFile.write(fileName)
    myFile.close()
    return IV

def Myencrypt(message, key):
    IV = generateIV()
    if len(key) < 32:
        print("Error, length of key is less than 32")
        return 0

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    ct = encryptor.update(message) + encryptor.finalize()
    return ct

def Mydecrypt():
    decryptor = cipher.decryptor()
    decryptor.update(ct) + decryptor.finalize()