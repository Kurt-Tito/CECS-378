import base64
import Myencrypt




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


def MyfileEncrypt(fileName):
    key = generateKey()
    pictureString = openPicture(fileName)
    Myencrypt(pictureString, key)

def MyfileDecrypt(fileName):

