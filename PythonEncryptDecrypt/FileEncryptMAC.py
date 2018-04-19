#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Apr 12 10:33:48 2018

@author: winn
"""
import os, sys, io, json, base64
from cryptography.hazmat.primitives import padding, serialization, hashes, asymmetric, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.PublicKey import RSA
from array import array
import binascii
from os import listdir
from os.path import isfile, join

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

def generateHMAC(HMACkey, message):
    	h = hmac.HMAC(HMACkey, hashes.SHA256(), backend=default_backend())
    	h.update(message)
    	tag = h.finalize    
    	return tag;   

    	def MyencryptMAC(message, EncKey, HMACKey):
    		if(len(EncKey) != 32 or len(HMACKey) != 32):
    			try:
    				raise Exception('ValueError')
    			except Exception as error:
    				print ("Encryption Key Length:", len(EncKey), "bytes")
    				print ("HMAC Key Length:", len(HMACKey), "bytes")
    				print ("The key(s) entered is not 32 byte.")
    				sys.exit(0)

    #Convert to bytes
    byteEncKey = bytes(EncKey, 'utf-8')
    byteHMACKey = bytes(HMACKey, 'utf-8')
    byteMessage = bytes(message, 'utf-8')
    
    #Pad message
    padder = padding.PKCS7(128).padder()
    padded_byteMessage = padder.update(byteMessage)
    padded_byteMessage += padder.finalize()
    
    #Generate IV
    iv = os.urandom(16)
    
    #Create AES CBC Cipher
    cipher = Cipher(algorithms.AES(byteEncKey), modes.CBC(iv), default_backend())
    
    #Encrypt cipher
    encryptor = cipher.encryptor()
    
    #Create ciphertext
    c = encryptor.update(padded_byteMessage) + encryptor.finalize()
    
    #HMAC
    h = hmac.HMAC(byteHMACKey, hashes.SHA256(), backend=default_backend())
    h.update(c)
    tag = h.finalize()
    
    #Return values 
    return c, iv, tag

def MydecryptMAC(c, iv, tag, encKey, HMACKey):
    #convert to bytes
        #c_bytes = binascii.unhexlify(c.encode('utf-8'))
        HMACKey_bytes = binascii.unhexlify(HMACKey.encode('utf-8'))
        encKey_bytes = binascii.unhexlify(encKey.encode('utf-8'))
        
    #Verify Tag
    h = hmac.HMAC(HMACKey_bytes, hashes.SHA256(), backend=default_backend())
    h.update(c)
    h.verify(tag)
    
    #Decrypting...
    cipher = Cipher(algorithms.AES(encKey_bytes), modes.CBC(iv), default_backend())
    decryptor = cipher.decryptor()
    message_bytes_padded = decryptor.update(c) + decryptor.finalize()
    
    #Unpadding...
    unpadder = padding.PKCS7(128).unpadder()
    message_bytes= unpadder.update(message_bytes_padded) + unpadder.finalize()
    
    #Convert to string
    message = message_bytes.decode('utf-8')
    
    #return message
    return message
    
def MyfileEncryptMAC(filepath):
    #Open file as bytes
    with open(filepath, "rb") as f:
    	byte_array = bytearray(f.read())
    	content = bytes(byte_array)

    #Generate keys
    encKey = os.urandom(32)
    HMACKey = os.urandom(32)

    #Get file extension
    filepath, ext = os.path.splitext(filepath)
    
    #Call Encrypt module
    enc = Encrypt(content, encKey)
        c = enc[0] #this is our encrypted message
        #print(c)
        iv = enc [1]
        
        #hash our encrypted message
        #h = generateHMAC(HMACKey, c) #this is the hash of the encrypted message
        
    #HMAC
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    h.update(c)
    tag = h.finalize()
    
    #convert to string 
        #hex_h = binascii.hexlify(h)
        c_string = binascii.hexlify(c).decode('utf-8')
        #h_string = hex_h.decode('utf-8')
        tag_string = binascii.hexlify(tag).decode('utf-8')
        iv_string = binascii.hexlify(iv).decode('utf-8')
        encKey_string = binascii.hexlify(encKey).decode('utf-8')
        HMACKey_string = binascii.hexlify(HMACKey).decode('utf-8')
        ext_string = str(ext)
        
        #print("File in bytes converted tos string")
        #print(c_string)

    #Write to JSON
    data = {'c': c_string,
    'iv': iv_string,
    'encKey': encKey_string,
    'HMACKey': HMACKey_string,
    'tag': tag_string,
    'ext': ext_string
    }
        #with open('C://Users//winn//Documents//GitHub//CECS-378//PythonEncryptDecrypt//data.json', 'w') as f:
        #with open('C://Users//TITO//Documents//California State University Long Beach//CSULB Spring 2018//CECS 378 LAB//CECS-378//PythonEncryptDecrypt//data.json', 'w') as f:
        with open('C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//HMACdata.json', 'w') as f:
        	json.dump(data, f)

        	return c, iv, encKey, HMACKey, tag, ext

        	def MyfileDecryptMAC():
        #with open('C://Users//winn//Documents//GitHub//CECS-378//PythonEncryptDecrypt//data.json', 'r') as f:
        with open('C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//HMACdata.json', 'r') as f:
        	data = json.load(f)

    #in bytes
    c = binascii.unhexlify(data['c'].encode('utf-8'))
    iv = binascii.unhexlify(data['iv'].encode('utf-8'))
    encKey = binascii.unhexlify(data['encKey'].encode('utf-8'))
    HMACKey = binascii.unhexlify(data['HMACKey'].encode('utf-8'))
    tag = binascii.unhexlify(data['tag'].encode('utf-8'))
    ext = data['ext']
    
    #Verify Tag
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    h.update(c)
    h.verify(tag)
    
    #Decrypting...
    cipher = Cipher(algorithms.AES(encKey), modes.CBC(iv), default_backend())
    decryptor = cipher.decryptor()
    originalfile_bytes_padded = decryptor.update(c) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(originalfile_bytes_padded)
    originalfile_bytes = data + unpadder.finalize()
    
    print(originalfile_bytes)
    
    #Save file 
    savefilePath = "C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//Output//MAC_FileEncrypt_output"
    savefilePath += str(ext)
    
    f = open(savefilePath, "wb")
    f.write(bytearray(originalfile_bytes))
    f.close()
    
def MydecryptMAC():

    #open and read rsa_data
    with open('C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//rsa_data.json', 'r') as f:
    	rsa_data = json.load(f)

    #ope, read, and store private key as var
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
    savefilePath = "C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//Output//NSA_Highly_Classified"
    savefilePath += str(ext)
    
    f = open(savefilePath, "wb")
    f.write(bytearray(originalfile_bytes))
    f.close()

def MyRSAEncryptMAC(filepath, RSA_PublicKey_filepath, fileNumber)    :

    #Encrypt file
    MyfileEncryptMAC(filepath)
    with open('C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//HMACdata.json', 'r') as f:
    	data = json.load(f)

    #in bytes
    c = binascii.unhexlify(data['c'].encode('utf-8'))
    iv = binascii.unhexlify(data['iv'].encode('utf-8'))
    encKey = binascii.unhexlify(data['encKey'].encode('utf-8'))
    HMACKey = binascii.unhexlify(data['HMACKey'].encode('utf-8'))
    ext = data['ext']
    
    #concatenate encryption key and hmac key
    m = encKey + HMACKey
    #open and read public key file
    with open (RSA_PublicKey_filepath, 'rb') as key_file:
    	public_key = serialization.load_pem_public_key(key_file.read(), default_backend())

    #Create cipher for public key
    RSACipher = public_key.encrypt(
    	m, 
    	asymmetric.padding.OAEP(
    		mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
    		algorithm=hashes.SHA256(),
    		label = None
    		)
    	)
    
    #Create tag
    digest = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    digest.update(c)
    tag = digest.finalize()
    
    #in string
    RSACipher_string = binascii.hexlify(RSACipher).decode('utf-8')
    c_string = binascii.hexlify(c).decode('utf-8')
    iv_string = binascii.hexlify(iv).decode('utf-8')
    tag_string = binascii.hexlify(tag).decode('utf-8')
    ext_string = ext
    
    #Write to JSON
    data = {'RSACipher': RSACipher_string, 
    'c': c_string,
    'iv': iv_string,
    'tag': tag_string,
    'ext': ext_string
    }
    
    #write data to rsa_data.json
    with open('C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//TestFolder//HMAC_rsa_data'+ fileNumber + '.json', 'w+') as f:
    	json.dump(data, f)

    #return RSACipher, bytes_c, bytes_iv, bytes_ext
    #return hex_RSACipher, hex_c, hex_iv, hex_ext
    
    #return 
    print (RSACipher, c, iv, tag, ext)
    return RSACipher, c, iv, tag, ext
    
def MyRSADecryptMAC(RSA_PrivateKey_filepath, fileNumber):

    #open and read rsa_data
    with open('C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//TestFolder//HMAC_rsa_data'+ fileNumber + '.json', 'r') as f:
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
    tag = binascii.unhexlify(rsa_data['tag'].encode('utf-8'))
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
    
    #splitting derived key into encryption key and decryption key
    encKey = key[0:32]
    HMACKey = key[32:64]
    
    #Verify Tag
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    h.update(c)
    h.verify(tag)
    
    
    #Decrypting...
    cipher = Cipher(algorithms.AES(encKey), modes.CBC(iv), default_backend())
    decryptor = cipher.decryptor()
    originalfile_bytes_padded = decryptor.update(c) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(originalfile_bytes_padded)
    originalfile_bytes = data + unpadder.finalize()
    
    print(originalfile_bytes)
    
    #Save file 
    savefilePath = "C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//TestFolder//RSA_output_MAC" + fileNumber
    savefilePath += str(ext)
    
    f = open(savefilePath, "wb")
    f.write(bytearray(originalfile_bytes))
    f.close()
    os.remove(rsa_data)

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
    mypath = "C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//TestFolder"
    RSA_PublicKey_filepath = 'C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//Keys//rsa_public_key.pem'
    RSA_PrivateKey_filepath = 'C://Users//Kurt Tito//Desktop//CECS-378//PythonEncryptDecrypt//Keys//rsa_private_key.pem'
    
    MyRSAEncryptMAC(filepath, RSA_PublicKey_filepath)
    MyRSADecryptMAC(RSA_PrivateKey_filepath)

    #Compile a list of filenames in he folder
    listOfFileNames = [f for f in listdir(mypath) if isfile(join(mypath, f))]
    #For each file, we're going to encrypt it using rsa encrypt
    counter = 0
    for i in listOfFileNames:
    	MyRSAEncryptMAC(i, RSA_PublicKey_filepath, counter)
    	counter++
    	while true:
    		input = print("Would you like to decrypt? Y/N")
    		input = input.upper()
    		if input == 'Y':
    			counter = 0
    			for i in listOfFileNames:
    				MyRSADecryptMAC(RSA_PrivateKey_filepath, counter)
    				counter++
    				break





