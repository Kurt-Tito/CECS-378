import os, sys
from cryptography.hazmat.primitives import padding, serialization, hashes, asymmetric
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.PublicKey import RSA

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
        #print(c)
        iv = enc [1]
    #return ct, iv, key, ext
    
    
        hex_key = binascii.hexlify(key)
        hex_iv = binascii.hexlify(iv)
        hex_c = binascii.hexlify(c)
        
        c_string = hex_c.decode('utf-8')
        iv_string = hex_iv.decode('utf-8')
        key_string = hex_key.decode('utf-8')
        ext_string = str(ext)
        
        #print("File in bytes converted tos string")
        #print(c_string)

    #Write to JSON
        data = {'c': c_string,
                'iv': iv_string,
                'key': key_string,
                'ext': ext_string
        }
        #with open('C://Users//winn//Documents//GitHub//CECS-378//PythonEncryptDecrypt//data.json', 'w') as f:
        #with open('C://Users//TITO//Documents//California State University Long Beach//CSULB Spring 2018//CECS 378 LAB//CECS-378//PythonEncryptDecrypt//data.json', 'w') as f:
        with open('C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//data.json', 'w') as f:
            json.dump(data, f)
    
def MyfileDecrypt():
    #Decrypt 
        #with open('C://Users//winn//Documents//GitHub//CECS-378//PythonEncryptDecrypt//data.json', 'r') as f:
        with open('C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//data.json', 'r') as f:
            data = json.load(f)

        content = Decrypt(data['c'], data['iv'], data['key'],)
        ext = data['ext']
    #Save file 
        #saveFile = "C://Users//winn//Documents//GitHub//CECS-378//PythonEncryptDecrypt//file"
        saveFile = "C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//file"
        saveFile += ext
        f = open(saveFile, "wb")
        #f.write(bytearray(content, 'utf-8'))
        f.write(bytearray(content))
        f.close

def MyRSAEncrypt(filepath, RSA_PublicKey_filepath):
    
    #Encrypt file and writes to data.json
        MyfileEncrypt(filepath)
    
    #Load json data
        with open('C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//data.json', 'r') as f:
            data = json.load(f)
    
    #in bytes
        c = binascii.unhexlify(data['c'].encode('utf-8'))
        iv = binascii.unhexlify(data['iv'].encode('utf-8'))
        key = binascii.unhexlify(data['key'].encode('utf-8'))
        ext = data['ext']
    
    #open and read public key file
        with open (RSA_PublicKey_filepath, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(key_file.read(), default_backend())
        
    #Create cipher for public key
        RSACipher = public_key.encrypt(
                key,
                asymmetric.padding.OAEP(
                        mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label = None
                        )
        )
    
    #in string
        RSACipher_string = binascii.hexlify(RSACipher).decode('utf-8')
        c_string = binascii.hexlify(c).decode('utf-8')
        iv_string = binascii.hexlify(iv).decode('utf-8')
        ext_string = ext
    
    #Write to JSON
        data = {'RSACipher': RSACipher_string, 
                'c': c_string,
                'iv': iv_string,
                'ext': ext_string
                }
   
    #write data to rsa_data.json
        with open('C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//rsa_data.json', 'w') as f:
            json.dump(data, f)
    
    #return RSACipher, bytes_c, bytes_iv, bytes_ext
    #return hex_RSACipher, hex_c, hex_iv, hex_ext
    
    #return 
        print (RSACipher, c, iv, ext)
        return RSACipher, c, iv, ext

def MyRSADecrypt(RSA_PrivateKey_filepath):
    
    #open and read rsa_data
        with open('C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//rsa_data.json', 'r') as f:
            rsa_data = json.load(f)
    
    #open, read, and store private key as var
        with open(RSA_PrivateKey_filepath, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password = None,
                    backend = default_backend()
                    )
       
    #in bytes
        RSACipher = binascii.unhexlify(rsa_data['RSACipher'].encode('utf-8'))
        c = binascii.unhexlify(rsa_data['c'].encode('utf-8'))
        iv = binascii.unhexlify(rsa_data['iv'].encode('utf-8'))
        ext = rsa_data['ext']
    
    #decrypt private key and store as key 
        key = private_key.decrypt(
            RSACipher,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )
    
    #Decrypting...
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
        decryptor = cipher.decryptor()
        originalfile_bytes_padded = decryptor.update(c) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(originalfile_bytes_padded)
        originalfile_bytes = data + unpadder.finalize()
    
        print(originalfile_bytes)
    
    #Save file 
        savefilePath = "C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//Output//output"
        savefilePath += str(ext)
    
        f = open(savefilePath, "wb")
        f.write(bytearray(originalfile_bytes))
        f.close()

def main():
    
    #Generate RSA key for key pairs
        new_key = RSA.generate(4096)
    
    #create and write public key 
        public_key = new_key.publickey().exportKey("PEM")
        f = open('C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//Keys//rsa_public_key.pem', 'wb')
        f.write(public_key)
        f.close()
    
    #create and write private key
        private_key = new_key.exportKey("PEM")
        f = open('C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//Keys//rsa_private_key.pem', 'wb')
        f.write(private_key)
        f.close()
    
    #Calling RSA Encryptor Decryptor modules
        filepath = "C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//unknown.png"
        RSA_PublicKey_filepath = 'C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//Keys//rsa_public_key.pem'
        RSA_PrivateKey_filepath = 'C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//Keys//rsa_private_key.pem'
    
        MyRSAEncrypt(filepath, RSA_PublicKey_filepath)
        MyRSADecrypt(RSA_PrivateKey_filepath)
