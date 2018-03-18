import os, sys
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import json
import binascii

def Encrypt(message, key):
    #Check if key is less than 32
        if (len(key) < 32):
            print ("This key is less than 32 bytes")
            sys.exit(0)

    #Convert key and message into bytes
        message_bytes = bytes(message)
        
        key_bytes = key
       
    #Create Padder
        padder = padding.PKCS7(128).padder()
    
    #Padding message in bytes
        padded_message_bytes = padder.update(message_bytes) + padder.finalize()
        
    #Generate random IV
        iv = os.urandom(16)
    
    #Creates AES CBC cipher
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), default_backend())
        
    #Encrypt cipher
        encryptor = cipher.encryptor()
    
    #Create ciphertext
        c = encryptor.update(padded_message_bytes) + encryptor.finalize()
        return c, iv
    
def Decrypt(c, iv, key):
    #Convert key to bytes
        key_bytes = binascii.unhexlify(key.encode('utf-8'))
    #Convert IV to bytes
        iv_bytes = binascii.unhexlify(iv.encode('utf-8'))
    #Convert c to bytes
        c_bytes = binascii.unhexlify(c.encode('utf-8'))    
        print("Cbytes converted from string back to bytes")
        print(c_bytes)
    #Create AES CBC cipher

        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), default_backend())

    #Create Decryptor for cipher
        decryptor = cipher.decryptor()
    
    #Original Message but in bytes with padding
        message_bytes_padded = decryptor.update(c_bytes) + decryptor.finalize()
        
    #Create unpadder
        unpadder = padding.PKCS7(256).unpadder()
    
    #Unpadding message in bytes
        message_bytes= unpadder.update(message_bytes_padded) + unpadder.finalize()
    
    #Convert message in bytes form to string
        return message_bytes
    
def MyfileEncrypt(filename):
    #Open file as bytes
        with open(filename, "rb") as f:
            byte_array = bytearray(f.read())
            content = bytes(byte_array)
        
    #Generate key
        key = os.urandom(32)

    #Get file extension
        filename, ext = os.path.splitext(filename)
    
    #Call Encrypt module
        enc = Encrypt(content, key)
        c = enc[0]
        print(c)
        iv = enc [1]
    #return ct, iv, key, ext
    
    
        hex_key = binascii.hexlify(key)
        hex_iv = binascii.hexlify(iv)
        hex_c = binascii.hexlify(c)
        
        c_string = hex_c.decode('utf-8')
        iv_string = hex_iv.decode('utf-8')
        key_string = hex_key.decode('utf-8')
        ext_string = str(ext)
        
        print("File in bytes converted tos string")
        print(c_string)

    #Write to JSON
        data = {'c': c_string,
                'iv': iv_string,
                'key': key_string,
                'ext': ext_string
        }
        with open('C://Users//winn//Documents//GitHub//CECS-378//PythonEncryptDecrypt//data.json', 'w') as f:
            json.dump(data, f)
    
    
    
def MyfileDecrypt():
    #Decrypt 
        with open('C://Users//winn//Documents//GitHub//CECS-378//PythonEncryptDecrypt//data.json', 'r') as f:
            data = json.load(f)

        content = Decrypt(data['c'], data['iv'], data['key'],)
        ext = data['ext']
    #Save file 
        saveFile = "C://Users//winn//Documents//GitHub//CECS-378//PythonEncryptDecrypt//file"
        saveFile += ext
        f = open(saveFile, "wb")
        #f.write(bytearray(content, 'utf-8'))
        f.write(bytearray(content))
        f.close


def main():
    filename = 'unknown.png'

    MyfileEncrypt(filename)

    MyfileDecrypt()
    