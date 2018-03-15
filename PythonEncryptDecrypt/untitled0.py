#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Mar  1 12:57:35 2018
@author: winn
"""

import os, sys
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def Encrypt(message, key):
    #Check if key is less than 32
        if (len(key) < 32):
            print ("This key is less than 32 bytes")
            sys.exit(0)
            
    #Convert key and message into bytes
        message_bytes = bytes(message, 'utf-8')
        key_bytes = bytes(key, 'utf-8')
       
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
        ciphertext = encryptor.update(padded_message_bytes) + encryptor.finalize()
        return ciphertext, iv
    

def Decrypt(ciphertext, iv, key):
    #Convert key to bytes
        key_bytes = bytes(key, 'utf-8')
        
    #Create AES CBC cipher
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), default_backend())

    #Create Decryptor for cipher
        decryptor = cipher.decryptor()
    
    #Original Message but in bytes with padding
        message_bytes_padded = decryptor.update(ciphertext) + decryptor.finalize()
        
    #Create unpadder
        unpadder = padding.PKCS7(128).unpadder()
    
    #Unpadding message in bytes
        message_bytes= unpadder.update(message_bytes_padded) + unpadder.finalize()
    
    #Convert message in bytes form to string
        message = message_bytes.decode('utf-8')
        return message
    
    
    