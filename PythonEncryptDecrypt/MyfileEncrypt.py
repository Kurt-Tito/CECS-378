import base64


def openPicture():
    with open("t.png", "rb") as imageFile:
        pictureString = base64.b64encode(imageFile.read())
    return pictureString

def createPicture(picture):
    fh = open("imageToSave.png", "wb")
    fh.write(picture.decode('base64'))
    fh.close()


def MyfileEncrypt():
