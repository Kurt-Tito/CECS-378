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
    #Exception to check if key is less than 32
        while (len(key) < 32):
            try:
                raise Exception('Value Error')
            except Exception as error:
                print ("This key is less than 32 bytes")
                sys.exit(0)
    #Convert key and message into bytes
        message_bytes = bytes(message, 'utf-8')
        key_bytes = bytes(key, 'utf-8')
       
    #Padding
        padder = padding.PKCS7(128).padder()
        padded_message_bytes = padder.update(message_bytes)
        padded_message_bytes += padder.finalize()
        
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
    #
    # WORK 
    # IN
    # PROGRESS
    #
    
    
    
    
    
        
    

