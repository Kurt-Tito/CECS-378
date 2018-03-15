import base64

def openPicture(fileName):
    with open("t.png", "rb") as imageFile:
        pictureString = base64.b64encode(imageFile.read())
    return pictureString

def createPicture(picture):
    fh = open("imageToSave.png", "wb")
    fh.write(picture.decode('base64'))
    fh.close()

def generateKey():
    key = os.urandom(32)
    fileName = "Key.txt"
    myFile = open(fileName, 'w')
    myFile.write(fileName)
    myFile.close()
    return key

#def MyfileEncrypt(fileName):
#    key = generateKey()
#    pictureString = openPicture(fileName)
#    Myencrypt(pictureString, key)

#def MyfileDecrypt(fileName):

##################################################################
    
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
        #message_bytes = bytes(message, 'utf-8')
        message_bytes = bytes(message)
        #key_bytes = bytes(key, 'utf-8')
        key_bytes = bytes(key)
       
    #Create Padder
        padder = padding.PKCS7(128).padder()
    
    #Padding message in bytes
        padded_message_bytes = padder.update(message_bytes) + padder.finalize()
        
    #Generate random IV
        iv = os.urandom(16)
        #iv_bytes = bytes(iv)
    
    #Creates AES CBC cipher
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), default_backend())
        
    #Encrypt cipher
        encryptor = cipher.encryptor()
    
    #Create ciphertext
        ciphertext = encryptor.update(padded_message_bytes) + encryptor.finalize()
        return ciphertext, iv
    
def Decrypt(ciphertext, iv, key):
    #Convert key to bytes
        #key_bytes = bytes(key, 'utf-8')
        #iv_bytes = bytes(iv, 'utf-8')
        key_bytes = bytes(key)
        #iv_bytes = bytes(iv)
        
    #Create AES CBC cipher
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), default_backend())

    #Create Decryptor for cipher
        decryptor = cipher.decryptor()
    
    #Original Message but in bytes with padding
        message_bytes_padded = decryptor.update(ciphertext) + decryptor.finalize()
        
    #Create unpadder
        unpadder = padding.PKCS7(256).unpadder()
    
    #Unpadding message in bytes
        message_bytes= unpadder.update(message_bytes_padded) + unpadder.finalize()
    
    #Convert message in bytes form to string
        #message = message_bytes.decode('utf-8')
        #message = message_bytes
        #return message
        return message_bytes
    
def MyfileEncrypt(filepath):
    #Open file as bytes
        with open(filepath, "rb") as f:
            #content = f.read()
            byte_array = bytearray(f.read())
            content = bytes(byte_array)
            #byte_string = bytes(byte_array)
        
    #Generate key
        key = os.urandom(32)
    
    #Get file extension
        filename, ext = os.path.splitext(filepath)
        
    #return
        return Encrypt(content, key), key, ext
    

def MyfileDecrypt(ciphertext, iv, key, ext):
    #Decrypt 
        #content = Decrypt(str(ciphertext), str(iv), str(key))
        content = Decrypt(ciphertext, iv, key)
    
    #Save file 
        saveFile = "C://Users//TITO//Desktop//TEST//file"
        saveFile += ext
        f = open(saveFile, "wb")
        #f.write(bytearray(content, 'utf-8'))
        f.write(bytearray(content))
        f.close
