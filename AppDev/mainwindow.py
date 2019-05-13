# -*- coding: utf-8 -*-

import os, shutil
import sys
import zipfile
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from PyQt5 import QtCore, QtGui, QtWidgets
from Crypto import Random
from Crypto.Random import random
from PIL import Image


class Enchipher:
    def __init__(self):
        # Sender's private key:
        self.priKey = "files/priKeySender.pem"
        # Receiver's public key:
        self.pubKey = "files/pubKeyReceiver.pem"

        # File name to encrypt
        self.f_name = ""

    def sigGenerator(self, priKey_fname, f_name, priPass):
        # Opening and reading file to encrypt

        f = open(f_name, "r")
        buffer = f.read()
        f.close()

        # Creating hash of the file. Using SHA-256 (SHA-512 rose problems)

        h = SHA256.new(buffer)

        # Reading private key to sign file with

        keyPair = RSA.importKey(open(priKey_fname, "r").read(), passphrase=priPass)
        keySigner = PKCS1_v1_5.new(keyPair)

        # Saving signature to *.sig file
        relative = f_name.split('/')[-1]
        f = open("files/" + relative.split('.')[0] + ".sig", "w+")
        f.write(keySigner.sign(h))
        f.close()

    def keyGenerator(self, pubKey_fname, f_name, iv):
        # Generating 1024 random bits, and creating SHA-256 (for 32 bits compatibility with AES)

        h = SHA256.new(str(random.getrandbits(1024)))

        # Reading public key to encrypt AES key with

        keyPair = RSA.importKey(open(pubKey_fname, "r").read())
        keyCipher = PKCS1_OAEP.new(keyPair.publickey())

        # Saving encrypted key to *.key file
        relative = f_name.split('/')[-1]
        f = open("files/" + relative.split('.')[0] + ".key", "w+")
        f.write(iv + keyCipher.encrypt(h.digest()))
        f.close()

        # Returning generated key to encrypt file with

        return h.digest()

    def encipher(self, keyA_fname, keyB_fname, f_name):
        # Opening file to encrypt in binary reading mode

        f = open(f_name, "rb")
        buffer = f.read()
        f.close()

        # Generating file's signature (and saving it)

        priPass = ""
        self.sigGenerator(keyA_fname, f_name, priPass=priPass)

        # Generating initializing vector for AES Encryption

        iv = Random.new().read(AES.block_size)

        # Generating symmetric key for use (and saving it)

        k = self.keyGenerator(keyB_fname, f_name, iv)

        # Encrypting and saving result to *.bin file. Using CFB mode

        keyCipher = AES.new(str(k), AES.MODE_CFB, iv)
        relative = f_name.split('/')[-1]
        f = open("files/" + relative.split('.')[0] + ".bin", "w+")
        f.write(keyCipher.encrypt(buffer))
        f.close()

    def auxFilesZip(self, sig, key, bin):
        # Opening file to contain all bin, sig and key files

        f = zipfile.ZipFile(bin.split('.')[0] + ".all", "w")

        # Writing each of the arguments to the created file

        f.write(sig)
        f.write(key)
        f.write(bin)

        # Closing the file

        f.close()

        # NOT Running clean up to the bin, sig and key files

    def cleanUp(self, sig, key, bin):
        # Deleting each of the files generated during ciphering

        os.remove(sig)
        os.remove(key)
        os.remove(bin)

    def checkFiles(self, f_name, pubKey, priKey):
        # Checking for encrypting file's existence and access

        if not os.path.isfile(f_name) or not os.access(f_name, os.R_OK):
            print ("Invalid file to encrypt. Aborting...")
            return "Invalid file to encrypt."

        # Checking for each of the files to create existence and, in case they exist, if they are writable

        else:
            s = f_name.split('.')[0]
            if os.path.isfile("files/" + s + ".sig") and not os.access(s + ".sig", os.W_OK):
                print "Can't create temporary file: *.bin. Aborting..."
                return "Can't create temporary file: *.bin."
            if os.path.isfile("files/" + s + ".key") and not os.access(s + ".key", os.W_OK):
                print "Can't create temporary file: *.key. Aborting..."
                return "Can't create temporary file: *.key."
            if os.path.isfile("files/" + s + ".bin") and not os.access(s + ".bin", os.W_OK):
                print "Can't create temporary file: *.bin. Aborting..."
                return "Can't create temporary file: *.bin."
            if os.path.isfile("files/" + s + ".all") and not os.access(s + ".all", os.W_OK):
                print "Can't create output file. Aborting..."
                return "Can't create output file."

        # Checking for public key's existence and access

        if not os.path.isfile(pubKey) or not os.access(pubKey, os.R_OK):
            print "Invalid public key file. Aborting..."
            return "Invalid public key file."

        # Checking for private key's existence and access

        if not os.path.isfile(priKey) or not os.access(priKey, os.R_OK):
            print "Invalid private key file. Aborting..."
            return "Invalid private key file."

        return 1

    # STEGANOGRAPHY

    def txt_encode(self, imp, text):
        Im = Image.open(imp)

        pixel = Im.load()
        pixel[0, 0] = (len(text) % 256, (len(text) // 256) % 256, (len(text) // 65536))

        try:
            for i in range(1, len(text) + 1):
                k = list(pixel[0, i])
                k[0] = int(k[0] / 10) * 10 + ord(text[i - 1]) // 100
                k[1] = int(k[1] / 10) * 10 + ((ord(text[i - 1]) // 10) % 10)
                k[2] = int(k[2] / 10) * 10 + ord(text[i - 1]) % 10
                pixel[0, i] = tuple(k)
        except IndexError:
            return False

        f_out_filename = str(imp).split('.')[0] + 'Encoded.png'
        f_out_filename = 'files/' + str(f_out_filename).rsplit('/', 1)[1]
        Im.save(f_out_filename)
        return True


class Decipher:
    def __init__(self):
        # Define public and private key names for faster usage
        self.pubKey = "files/pubKeySender.pem"
        # Receiver's private key:
        self.priKey = "files/priKeyReceiver.pem"

        # File name to decrypt
        self.f_name = ""

        self.is_authentic = False

    def sigVerification(self, pubKey_fname, f_name):
        # Generating decrypted file's SHA-256

        h = SHA256.new()
        h.update(open(f_name, "r").read())

        # Reading public key to check signature with

        keyPair = RSA.importKey(open(pubKey_fname, "r").read())
        keyVerifier = PKCS1_v1_5.new(keyPair.publickey())

        # If signature is right, prints SHA-256. Otherwise states that the file is not authentic

        if keyVerifier.verify(h, open(f_name.split('.')[0] + ".sig", "r").read()):
            print("The signature is authentic.")
            self.is_authentic = True
            print("SHA-256 -> %s" % h.hexdigest())
            return True
        else:
            print("The signature is not authentic.")
            return False

    def keyReader(self, privKey_fname, f_name):
        # Reading private key to decipher symmetric key used

        keyPair = RSA.importKey(open(privKey_fname, "r").read())
        keyDecipher = PKCS1_OAEP.new(keyPair)

        # Reading iv and symmetric key used during encryption

        f = open(f_name.split('.')[0] + ".key", "r")
        iv = f.read(16)

        print privKey_fname, "\n", f_name
        try:
            k = keyDecipher.decrypt(f.read())
        except TypeError:
            return 0, "Invalid key."
        except ValueError:
            return 0, "Invalid key."

        return k, iv

    def decipher(self, keyA_fname, keyB_fname, f_name):
        # Getting symmetric key used and iv value generated at encryption process

        k, iv = self.keyReader(keyB_fname, f_name)

        if k != 0:
            # Deciphering the initial information and saving it to file with no extension

            keyDecipher = AES.new(k, AES.MODE_CFB, iv)
            bin = open(f_name + ".bin", "rb").read()
            print "Decipher output: " + str(f_name)
            f = open(f_name.split('.')[0], "wb")
            f.write(keyDecipher.decrypt(bin))
            f.close()

            # Running a Signature verification

            sig_verified = self.sigVerification(keyA_fname, f_name.split('.')[0])

            if sig_verified is False:
                return "sig_false"
            else:
                return "success"
        else:
            return iv

    def auxFilesUnzip(self, all):
        # Opening the input file

        f = zipfile.ZipFile(all + ".all", "r")

        # Extracting all of its files

        f.extractall()

    def cleanUp(self, sig, key, bin, all):
        # Removing all of the files created, except for the final deciphered file

        os.remove(sig)
        os.remove(key)
        os.remove(bin)
        os.remove(all)

    def checkFiles(self, f_name, pubKey, priKey, first_run):
        # Checking for decrypting file's existence and access, keys, aux and output files

        if first_run:
            # Checking for decrypting file's existence and access

            if not os.path.isfile(f_name + ".all") or not os.access(f_name + ".all", os.R_OK):
                print("Invalid file to decrypt. Aborting...")
                return "Invalid file to decrypt."

            # Checking for public key's existence and access

            if not os.path.isfile(pubKey) or not os.access(pubKey, os.R_OK):
                print("Invalid public key file. Aborting...")
                return "Invalid public key file."

            # Checking for private key's existence and access

            if not os.path.isfile(priKey) or not os.access(priKey, os.R_OK):
                print("Invalid private key file. Aborting...")
                return "Invalid private key file."

        elif not first_run:
            # Checking if all of the necessary files exist and are accessible

            if not os.path.isfile(f_name + ".sig") or not os.access(f_name + ".sig", os.R_OK):
                print("Invalid *.sig file. Aborting...")
                return "Invalid *.sig file."
            if not os.path.isfile(f_name + ".key") or not os.access(f_name + ".key", os.R_OK):
                print("Invalid *.key file. Aborting...")
                return "Invalid *.key file."
            if not os.path.isfile(f_name + ".bin") or not os.access(f_name + ".bin", os.R_OK):
                print("Invalid *.bin file. Aborting...")
                return "Invalid *.bin file."

            # Checking if in case of output file's existence, it is writable

            if os.path.isfile(f_name) and not os.access(f_name, os.W_OK):
                print("Can't create output file. Aborting...")
                return "Can't create output file."

        return 1

    def txt_decode(self, imp):
        imp = os.path.abspath(imp)
        Im = Image.open(imp)
        pixels = Im.load()
        size = (pixels[0, 0][0]) + (pixels[0, 0][1]) * 256 + (pixels[0, 0][2]) * 65536
        t = []

        for i in range(1, size + 1):
            t.append(chr((pixels[0, i][0] % 10) * 100 + (pixels[0, i][1] % 10) * 10 + (pixels[0, i][2] % 10)))

        te = "".join(t)
        return te


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):

        # initialize crypto classes
        self.decipher = Decipher()
        self.encipher = Enchipher()

        # generate the keys
        self.generate_keys()

        # for translation (used for setting text content for elements)
        self._translate = QtCore.QCoreApplication.translate

        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(914, 520)

        self.centralWidget = QtWidgets.QWidget(MainWindow)
        self.centralWidget.setObjectName("centralWidget")

        # BUTTON FOR EXECUTING CODE BEHIND

        self.button_execute = QtWidgets.QPushButton(self.centralWidget)  # button to DECRYPT or ENCRYPT
        self.button_execute.setEnabled(False)  # depending on state
        self.button_execute.setGeometry(QtCore.QRect(50, 410, 111, 51))
        self.button_execute.setMaximumSize(QtCore.QSize(111, 16777215))
        self.button_execute.setObjectName("decryptButton")
        self.button_execute.clicked.connect(self.execution)

        # OUTPUT or INPUT field
        # self.textedit_io = QtWidgets.QLineEdit(self.centralWidget)
        self.textedit_io = QtWidgets.QTextEdit(self.centralWidget)
        self.textedit_io.setGeometry(QtCore.QRect(280, 100, 541, 321))
        self.textedit_io.setText("")
        self.textedit_io.setReadOnly(True)
        self.textedit_io.setObjectName("label")
        self.textedit_inputtext = ""
        self.textedit_outputtext = ""

        # INPUT or OUTPUT label, depending on state
        self.label_io = QtWidgets.QLabel(self.centralWidget)
        self.label_io.setGeometry(QtCore.QRect(510, 60, 81, 31))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_io.setFont(font)
        self.label_io.setObjectName("label_2")

        # RADIOBUTTONS FOR MODE SWITCHING

        self.radioButton_encrypt = QtWidgets.QRadioButton(self.centralWidget)
        self.radioButton_encrypt.setGeometry(QtCore.QRect(350, 30, 112, 23))
        self.radioButton_encrypt.setObjectName("radioButton")
        self.radioButton_encrypt.setEnabled(True)
        self.radioButton_encrypt.clicked.connect(lambda: self.switch_mode())  # switch to encryption layout

        self.radioButton_decrypt = QtWidgets.QRadioButton(self.centralWidget)
        self.radioButton_decrypt.setGeometry(QtCore.QRect(490, 30, 112, 23))
        self.radioButton_decrypt.setChecked(False)
        self.radioButton_decrypt.setObjectName("radioButton_2")
        self.radioButton_decrypt.clicked.connect(lambda: self.switch_mode())  # switch to decryption layout

        # MESSAGE FOR ENCRYPTION

        self.label_message_fp = QtWidgets.QLabel(self.centralWidget)
        self.label_message_fp.setGeometry(QtCore.QRect(50, 110, 151, 16))
        self.label_message_fp.setObjectName("label_message_fp")
        self.label_message_fp.hide()

        self.message_filepicker_result = QtWidgets.QLineEdit(self.centralWidget)  # message filepicker
        self.message_filepicker_result.setGeometry(QtCore.QRect(50, 130, 171, 21))
        self.message_filepicker_result.setReadOnly(True)
        self.message_filepicker_result.setObjectName("filepicker_result")
        self.message_filepicker_result.hide()
        self.message_filepicker_button = QtWidgets.QPushButton(self.centralWidget)
        self.message_filepicker_button.setGeometry(QtCore.QRect(200, 130, 21, 21))
        self.message_filepicker_button.setText("")
        self.message_filepicker_button.setObjectName("filepicker_button")
        self.message_filepicker_button.clicked.connect(lambda: self.getfiles('msg_send'))
        self.message_filepicker_button.hide()
        self.message_path = ""  # used to store path of file(idem for all others under this)

        # IMAGE FOR STEGANOGRAPHY (optional)

        self.steganography = False
        self.label_image_fp = QtWidgets.QLabel(self.centralWidget)
        self.label_image_fp.setGeometry(QtCore.QRect(50, 160, 151, 16))
        self.label_image_fp.setObjectName("label_image_fp")
        self.label_image_fp.hide()

        self.image_filepicker_result = QtWidgets.QLineEdit(self.centralWidget)  # image filepicker
        self.image_filepicker_result.setGeometry(QtCore.QRect(50, 180, 171, 21))
        self.image_filepicker_result.setReadOnly(True)
        self.image_filepicker_result.setObjectName("image_filepicker_result")
        self.image_filepicker_result.hide()
        self.image_filepicker_button = QtWidgets.QPushButton(self.centralWidget)
        self.image_filepicker_button.setGeometry(QtCore.QRect(200, 180, 21, 21))
        self.image_filepicker_button.setText("")
        self.image_filepicker_button.setObjectName("image_filepicker_button")
        self.image_filepicker_button.clicked.connect(lambda: self.getfiles('image_send'))
        self.image_filepicker_button.hide()
        self.image_remove_button = QtWidgets.QPushButton(self.centralWidget)
        self.image_remove_button.setGeometry(QtCore.QRect(223, 180, 21, 21))
        self.image_remove_button.setText("X")
        self.image_remove_button.setObjectName("image_filepicker_button")
        self.image_remove_button.clicked.connect(lambda: self.remove_image())
        self.image_remove_button.hide()
        self.image_path = ""  # used to store path of file(idem for all others under this)

        # ENCRYPTED IMAGE

        self.label_encryptedimage_fp = QtWidgets.QLabel(self.centralWidget)
        self.label_encryptedimage_fp.setGeometry(QtCore.QRect(50, 110, 170, 16))
        self.label_encryptedimage_fp.setObjectName("encryptedimage_label")

        self.encrypted_image_filepicker_result = QtWidgets.QLineEdit(self.centralWidget)  # message filepicker
        self.encrypted_image_filepicker_result.setGeometry(QtCore.QRect(50, 130, 171, 21))
        self.encrypted_image_filepicker_result.setReadOnly(True)
        self.encrypted_image_filepicker_result.setObjectName("filepicker_result")

        self.encrypted_image_filepicker_button = QtWidgets.QPushButton(self.centralWidget)
        self.encrypted_image_filepicker_button.setGeometry(QtCore.QRect(200, 130, 21, 21))
        self.encrypted_image_filepicker_button.setText("")
        self.encrypted_image_filepicker_button.setObjectName("filepicker_button")
        self.encrypted_image_filepicker_button.clicked.connect(lambda: self.getfiles('image_receive'))
        self.encrypted_image_path = ""

        # FILES REMOVER BUTTON

        self.remove_files_button = QtWidgets.QPushButton(self.centralWidget)
        self.remove_files_button.setGeometry(QtCore.QRect(50, 220, 171, 21))
        self.remove_files_button.setText('Remove Files')
        self.remove_files_button.setObjectName('remove_files_button')
        self.remove_files_button.clicked.connect(lambda: self.deleteFiles())

        self.label_fileremover = QtWidgets.QLabel(self.centralWidget)
        self.label_fileremover.setGeometry(QtCore.QRect(50, 250, 170, 16))
        self.label_fileremover.setObjectName("fileremover_label")

        # ENCRYPTED MESSAGE

        self.label_encryptedmessage_fp = QtWidgets.QLabel(self.centralWidget)
        self.label_encryptedmessage_fp.setGeometry(QtCore.QRect(50, 110, 170, 16))
        self.label_encryptedmessage_fp.setObjectName("label_3")

        self.encrypted_msg_filepicker_result = QtWidgets.QLineEdit(self.centralWidget)  # message filepicker
        self.encrypted_msg_filepicker_result.setGeometry(QtCore.QRect(50, 130, 171, 21))
        self.encrypted_msg_filepicker_result.setReadOnly(True)
        self.encrypted_msg_filepicker_result.setObjectName("filepicker_result")
        self.encrypted_msg_filepicker_button = QtWidgets.QPushButton(self.centralWidget)
        self.encrypted_msg_filepicker_button.setGeometry(QtCore.QRect(200, 130, 21, 21))
        self.encrypted_msg_filepicker_button.setText("")
        self.encrypted_msg_filepicker_button.setObjectName("filepicker_button")
        self.encrypted_msg_filepicker_button.clicked.connect(lambda: self.getfiles('msg'))
        self.encrypted_msg_path = ""  # used to store path of file (idem for all others under this)

        # ENCRYPTED KEY

        self.label_encryptedkey_fp = QtWidgets.QLabel(self.centralWidget)
        self.label_encryptedkey_fp.setGeometry(QtCore.QRect(50, 160, 170, 16))
        self.label_encryptedkey_fp.setObjectName("label_4")

        self.encrypted_key_filepicker_result = QtWidgets.QLineEdit(self.centralWidget)
        self.encrypted_key_filepicker_result.setGeometry(QtCore.QRect(50, 180, 171, 21))
        self.encrypted_key_filepicker_result.setReadOnly(True)
        self.encrypted_key_filepicker_result.setObjectName("filepicker_result")
        self.encrypted_key_filepicker_button = QtWidgets.QPushButton(self.centralWidget)
        self.encrypted_key_filepicker_button.setGeometry(QtCore.QRect(200, 180, 21, 21))
        self.encrypted_key_filepicker_button.setText("")
        self.encrypted_key_filepicker_button.setObjectName("filepicker_button")
        self.encrypted_key_filepicker_button.clicked.connect(lambda: self.getfiles('key'))
        self.encrypted_key_path = ""

        # ENCRYPTED HASH

        self.label_encryptedhash_fp = QtWidgets.QLabel(self.centralWidget)
        self.label_encryptedhash_fp.setGeometry(QtCore.QRect(50, 210, 170, 16))
        self.label_encryptedhash_fp.setObjectName("label_5")

        self.encrypted_hash_filepicker_result = QtWidgets.QLineEdit(self.centralWidget)
        self.encrypted_hash_filepicker_result.setGeometry(QtCore.QRect(50, 230, 171, 21))
        self.encrypted_hash_filepicker_result.setReadOnly(True)
        self.encrypted_hash_filepicker_result.setObjectName("filepicker_result")
        self.encrypted_hash_filepicker_button = QtWidgets.QPushButton(self.centralWidget)
        self.encrypted_hash_filepicker_button.setGeometry(QtCore.QRect(200, 230, 21, 21))
        self.encrypted_hash_filepicker_button.setText("")
        self.encrypted_hash_filepicker_button.setObjectName("filepicker_button")
        self.encrypted_hash_filepicker_button.clicked.connect(lambda: self.getfiles('hash'))
        self.encrypted_hash_path = ""

        # PUBLIC KEY

        self.label_publickey_fp = QtWidgets.QLabel(self.centralWidget)
        self.label_publickey_fp.setGeometry(QtCore.QRect(50, 260, 140, 16))
        self.label_publickey_fp.setObjectName("label_6")

        self.publickey_filepicker_result = QtWidgets.QLineEdit(self.centralWidget)
        self.publickey_filepicker_result.setGeometry(QtCore.QRect(50, 280, 171, 21))
        self.publickey_filepicker_result.setReadOnly(True)
        self.publickey_filepicker_result.setObjectName("filepicker_result")
        self.publickey_filepicker_button = QtWidgets.QPushButton(self.centralWidget)
        self.publickey_filepicker_button.setGeometry(QtCore.QRect(200, 280, 21, 21))
        self.publickey_filepicker_button.setText("")
        self.publickey_filepicker_button.setObjectName("filepicker_button")
        self.publickey_filepicker_button.clicked.connect(lambda: self.getfiles('publickey'))
        self.publickey_path = ""

        # PRIVATE KEY

        self.label_privatekey_fp = QtWidgets.QLabel(self.centralWidget)
        self.label_privatekey_fp.setGeometry(QtCore.QRect(50, 310, 140, 16))
        self.label_privatekey_fp.setObjectName("label_7")

        self.privatekey_filepicker_result = QtWidgets.QLineEdit(self.centralWidget)
        self.privatekey_filepicker_result.setGeometry(QtCore.QRect(50, 330, 171, 21))
        self.privatekey_filepicker_result.setReadOnly(True)
        self.privatekey_filepicker_result.setObjectName("filepicker_result")
        self.privatekey_filepicker_button = QtWidgets.QPushButton(self.centralWidget)
        self.privatekey_filepicker_button.setGeometry(QtCore.QRect(200, 330, 21, 21))
        self.privatekey_filepicker_button.setText("")
        self.privatekey_filepicker_button.setObjectName("filepicker_button")
        self.privatekey_filepicker_button.clicked.connect(lambda: self.getfiles('privatekey'))
        self.privatekey_path = ""

        self.label_hashchecker = QtWidgets.QLabel(self.centralWidget)
        self.label_hashchecker.setGeometry(QtCore.QRect(420, 450, 161, 21))
        self.label_hashchecker.setObjectName("label_8")

        # mainwindow setup
        MainWindow.setCentralWidget(self.centralWidget)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
        self.switch_mode()

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(self._translate("MainWindow", "Basic Security"))
        self.button_execute.setText(self._translate("MainWindow", "DECRYPT"))
        self.label_io.setText(self._translate("MainWindow", "OUTPUT"))
        self.radioButton_encrypt.setText(self._translate("MainWindow", "ENCRYPT"))
        self.radioButton_decrypt.setText(self._translate("MainWindow", "DECRYPT"))
        self.label_message_fp.setText(self._translate("MainWindow", "Message"))
        self.label_image_fp.setText(self._translate("MainWindow", "Image (optional)"))
        self.label_encryptedimage_fp.setText(self._translate("MainWindow", "Encrypted image (.png)"))
        self.label_encryptedmessage_fp.setText(self._translate("MainWindow", "Encrypted message (.bin)"))
        self.label_encryptedkey_fp.setText(self._translate("MainWindow", "Encrypted key (.key)"))
        self.label_encryptedhash_fp.setText(self._translate("MainWindow", "Encrypted hash (.sig)"))
        self.label_publickey_fp.setText(self._translate("MainWindow", "Public key sender"))
        self.label_privatekey_fp.setText(self._translate("MainWindow", "Private key receiver"))
        self.label_hashchecker.setText(self._translate("MainWindow", "Hashcheck ..."))
        self.label_fileremover.setText(self._translate("MainWindow", "Also regenerates keys."))

    def switch_mode(self):
        if self.radioButton_encrypt.isEnabled():
            self.mode = 1
        else:
            self.mode = 2

        if self.mode == 1:  # encryption
            self.radioButton_encrypt.setEnabled(False)
            self.radioButton_decrypt.setEnabled(True)

            self.label_hashchecker.hide()
            self.label_io.setText(self._translate("MainWindow", "INPUT"))
            self.button_execute.setText(self._translate("MainWindow", "ENCRYPT"))
            self.label_encryptedmessage_fp.hide()
            self.label_encryptedkey_fp.hide()
            self.label_encryptedhash_fp.hide()
            self.label_publickey_fp.hide()
            self.label_privatekey_fp.hide()
            self.encrypted_hash_filepicker_result.hide()
            self.encrypted_hash_filepicker_button.hide()
            self.encrypted_key_filepicker_button.hide()
            self.encrypted_key_filepicker_result.hide()
            self.encrypted_msg_filepicker_result.hide()
            self.encrypted_msg_filepicker_button.hide()
            self.privatekey_filepicker_result.hide()
            self.privatekey_filepicker_button.hide()
            self.publickey_filepicker_result.hide()
            self.publickey_filepicker_button.hide()
            self.label_encryptedimage_fp.hide()
            self.encrypted_image_filepicker_button.hide()
            self.encrypted_image_filepicker_result.hide()

            self.message_filepicker_button.show()
            self.message_filepicker_result.show()
            self.label_message_fp.show()
            self.image_filepicker_button.show()
            self.image_filepicker_result.show()
            self.label_image_fp.show()
            self.image_remove_button.show()
            self.remove_files_button.show()
            self.label_fileremover.show()

            self.textedit_io.setText(self.textedit_inputtext)

        elif self.mode == 2:  # decryption
            self.radioButton_decrypt.setEnabled(False)
            self.radioButton_encrypt.setEnabled(True)

            self.label_io.setText(self._translate("MainWindow", "OUTPUT"))
            self.button_execute.setText(self._translate("MainWindow", "DECRYPT"))

            if self.steganography:
                self.label_encryptedimage_fp.show()
                self.encrypted_image_filepicker_button.show()
                self.encrypted_image_filepicker_result.show()
            else:
                self.label_hashchecker.show()
                self.label_encryptedmessage_fp.show()
                self.label_encryptedkey_fp.show()
                self.label_encryptedhash_fp.show()
                self.label_publickey_fp.show()
                self.label_privatekey_fp.show()
                self.encrypted_hash_filepicker_result.show()
                self.encrypted_hash_filepicker_button.show()
                self.encrypted_key_filepicker_button.show()
                self.encrypted_key_filepicker_result.show()
                self.encrypted_msg_filepicker_result.show()
                self.encrypted_msg_filepicker_button.show()
                self.privatekey_filepicker_result.show()
                self.privatekey_filepicker_button.show()
                self.publickey_filepicker_result.show()
                self.publickey_filepicker_button.show()

            self.message_filepicker_button.hide()
            self.message_filepicker_result.hide()
            self.label_message_fp.hide()
            self.image_filepicker_button.hide()
            self.image_filepicker_result.hide()
            self.label_image_fp.hide()
            self.image_remove_button.hide()
            self.remove_files_button.hide()
            self.label_fileremover.hide()

            self.textedit_inputtext = self.textedit_io.toPlainText()
            self.textedit_io.setText(self.textedit_outputtext)

        self.button_active_check()

    def getfiles(self, type):
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog
        fileName, _ = QtWidgets.QFileDialog.getOpenFileName(None, "QFileDialog.getOpenFileName()", "",
                                                            "All Files (*);;Python Files (*.py)", options=options)
        if fileName:
            result = ""
            reversed_filename = fileName[::-1]
            for i in range(len(reversed_filename)):
                letter = reversed_filename[i]
                if not (letter == '/' or letter == '\\'):
                    result = letter + result
                else:
                    break
            if type == 'msg':
                self.encrypted_msg_filepicker_result.setText(result)
                self.encrypted_msg_path = fileName
            elif type == 'msg_send':
                self.message_filepicker_result.setText(result)
                self.message_path = fileName
                f = open(fileName, 'r')
                input_msg = f.read()
                self.textedit_io.setText(input_msg)
            elif type == 'image_send':
                if str(fileName).split('.')[1].upper() in ['PPM', 'PNG', 'JPEG', 'GIF', 'TIFF', 'BMP']:
                    self.steganography = True
                    self.image_filepicker_result.setText(result)
                    self.image_path = fileName
                    if len(self.textedit_inputtext) > 0:
                        self.textedit_io.setText(self.textedit_inputtext)
                else:
                    self.textedit_io.setText('Image must be of type PPM, PNG, JPEG, GIF, TIFF or BMP')
            elif type == 'image_receive':
                if str(fileName).split('.')[1].upper() == 'PNG':
                    self.encrypted_image_filepicker_result.setText(result)
                    self.encrypted_image_path = fileName
                else:
                    self.textedit_io.setText('Image must be of type PNG')
            elif type == 'key':
                self.encrypted_key_filepicker_result.setText(result)
                self.encrypted_key_path = fileName
            elif type == 'hash':
                self.encrypted_hash_filepicker_result.setText(result)
                self.encrypted_hash_path = fileName
            elif type == 'publickey':
                self.publickey_filepicker_result.setText(result)
                self.publickey_path = fileName
            elif type == 'privatekey':
                self.privatekey_filepicker_result.setText(result)
                self.privatekey_path = fileName

        self.button_active_check()

    def deleteFiles(self):
        for the_file in os.listdir('files/'):
            file_path = os.path.join('files/', the_file)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print(self.textedit_io.setText('Error occurred while deleting files.'))

        self.generate_keys()

    # CHECK IF BUTTON SHOULD BE ACTIVE
    def button_active_check(self):
        if self.mode == 1:
            if not self.message_path == '':
                self.button_execute.setEnabled(True)
            else:
                self.button_execute.setEnabled(False)
        elif self.mode == 2:
            if not (self.encrypted_msg_path == '' or self.encrypted_key_path == '' or self.encrypted_hash_path == ''
                    or self.publickey_path == '' or self.privatekey_path == '') or not self.encrypted_image_path == '':
                self.button_execute.setEnabled(True)
            else:
                self.button_execute.setEnabled(False)

    def edit_text(self):
        self.textedit_inputtext = self.textedit_io.text()
        print(self.textedit_inputtext)

    # EXECUTE ENCRYPTION OR DECRYPTION
    def execution(self):

        self.label_hashchecker.setText('Hashcheck ...')
        if self.mode == 1:
            if self.steganography:
                if not self.encipher.txt_encode(self.image_path, self.textedit_io.toPlainText()):
                    self.textedit_io.setText('Failed to encode. Message too long?')
            else:
                self.encipher.encipher('files/priKeySender.pem', 'files/pubKeyReceiver.pem', self.message_path)
                self.encipher.auxFilesZip("files/" + self.message_filepicker_result.text().split('.')[0] + ".sig",
                                          "files/" + self.message_filepicker_result.text().split('.')[0] + ".key",
                                          "files/" + self.message_filepicker_result.text().split('.')[0] + ".bin")
            print "MESSAGE ENCRYPTED"

        elif self.mode == 2:
            print self.steganography

            if self.steganography:
                text = self.decipher.txt_decode(self.encrypted_image_path)
                print 'Returned text: ' + text
                self.textedit_io.setText(text)
            else:
                fileName = self.encrypted_msg_path.split('.')[0]
                print "Filename: " + fileName
                check_files_result = self.decipher.checkFiles(fileName, self.publickey_path, self.privatekey_path, False)
                print "Check_files_result: " + str(check_files_result)

                if check_files_result == 1:
                    decipher_result = self.decipher.decipher(self.publickey_path, self.privatekey_path, fileName)
                    print "Decipher result: " + str(decipher_result)

                    if decipher_result == 'success':
                        self.decipher.cleanUp(fileName + ".sig", fileName + ".key", fileName + ".bin", fileName + ".all")
                        print "MESSAGE DECRYPTED"
                        f = open(fileName).read()
                        self.textedit_io.setText(f)
                        if self.decipher.is_authentic:
                            self.label_hashchecker.setText("HASHCHECK OK")

                    elif decipher_result == 'sig_false':
                        self.textedit_io.setText('The signature is not authentic.')
                        self.label_hashchecker.setText("HASHCHECK NOT OK")

                    else:
                        self.textedit_io.setText(decipher_result)

                else:
                    self.textedit_io.setText(check_files_result)

    # GENERATE KEY PAIRS FOR SENDER AND RECEIVER
    def generate_keys(self):

        keyPair = RSA.generate(1024)

        # For PrivateKey Generation

        f = open("files/priKeySender.pem", "wb")
        f.write(keyPair.exportKey("PEM"))
        f.close()

        # For PublicKey Generation

        f = open("files/pubKeySender.pem", "wb")
        f.write(str(keyPair.publickey().exportKey()))
        f.close()

        keyPair = RSA.generate(1024)

        f = open("files/priKeyReceiver.pem", "wb")
        f.write(keyPair.exportKey("PEM"))
        f.close()

        f = open("files/pubKeyReceiver.pem", "wb")
        f.write(str(keyPair.publickey().exportKey()))
        f.close()

    def remove_image(self):
        self.steganography = False
        self.image_path = ''
        self.image_filepicker_result.setText('')


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
