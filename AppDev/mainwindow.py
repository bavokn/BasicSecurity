# -*- coding: utf-8 -*-

import os
import sys
import zipfile
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from PyQt5 import QtCore, QtGui, QtWidgets
from Crypto import Random
from Crypto.Random import random


class Enchipher:
    def __init__(self):
        # Sender's private key:
        self.priKey = "files/priKeyA.pem"
        # Receiver's public key:
        self.pubKey = "files/pubKeyB.pem"

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

        f = open(f_name.split('.')[0] + ".sig", "w")
        f.write(keySigner.sign(h))
        f.close()

    def keyGenerator(self, pubKey_fname, f_name, iv):
        # Generating 1024 random bits, and creating SHA-256 (for 32 bits compatibility with AES)

        h = SHA256.new(str(random.getrandbits(1024)))

        # Reading public key to encrypt AES key with

        keyPair = RSA.importKey(open(pubKey_fname, "r").read())
        keyCipher = PKCS1_OAEP.new(keyPair.publickey())

        # Saving encrypted key to *.key file

        f = open(f_name.split('.')[0] + ".key", "w")
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
        f = open(f_name.split('.')[0] + ".bin", "wb")
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

        # Running clean up to the bin, sig and key files

        self.cleanUp(sig, key, bin)

    def cleanUp(self, sig, key, bin):
        # Deleting each of the files generated during ciphering

        os.remove(sig)
        os.remove(key)
        os.remove(bin)

    def checkFiles(self, f_name, pubKey, priKey):
        # Checking for encrypting file's existence and access

        if not os.path.isfile(f_name) or not os.access(f_name, os.R_OK):
            print ("Invalid file to encrypt. Aborting...")
            sys.exit(1)

        # Checking for each of the files to create existence and, in case they exist, if they are writable

        else:
            s = f_name.split('.')[0]
            if os.path.isfile(s + ".sig") and not os.access(s + ".sig", os.W_OK):
                print "Can't create temporary file: *.bin. Aborting..."
                sys.exit(2)
            if os.path.isfile(s + ".key") and not os.access(s + ".key", os.W_OK):
                print "Can't create temporary file: *.key. Aborting..."
                sys.exit(3)
            if os.path.isfile(s + ".bin") and not os.access(s + ".bin", os.W_OK):
                print "Can't create temporary file: *.bin. Aborting..."
                sys.exit(4)
            if os.path.isfile(s + ".all") and not os.access(s + ".all", os.W_OK):
                print "Can't create output file. Aborting..."
                sys.exit(5)

        # Checking for public key's existence and access

        if not os.path.isfile(pubKey) or not os.access(pubKey, os.R_OK):
            print "Invalid public key file. Aborting..."
            sys.exit(6)

        # Checking for private key's existence and access

        if not os.path.isfile(priKey) or not os.access(priKey, os.R_OK):
            print "Invalid private key file. Aborting..."
            sys.exit(7)


class Decipher:
    def __init__(self):
        # Define public and private key names for faster usage
        self.pubKey = "files/pubKeyA.pem"
        # Receiver's private key:
        self.priKey = "files/priKeyB.pem"

        # File name to decrypt
        self.f_name = "files/encrypted_message.txt"

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
            print("SHA-256 -> %s" % h.hexdigest())
        else:
            print("The signature is not authentic.")

    def keyReader(self, privKey_fname, f_name):
        # Reading private key to decipher symmetric key used

        keyPair = RSA.importKey(open(privKey_fname, "r").read())
        keyDecipher = PKCS1_OAEP.new(keyPair)

        # Reading iv and symmetric key used during encryption

        f = open(f_name.split('.')[0] + ".key", "r")
        iv = f.read(16)
        k = keyDecipher.decrypt(f.read())

        return k, iv

    def decipher(self, keyA_fname, keyB_fname, f_name):
        # Getting symmetric key used and iv value generated at encryption process

        k, iv = self.keyReader(keyB_fname, f_name)

        # Deciphering the initial information and saving it to file with no extension

        keyDecipher = AES.new(k, AES.MODE_CFB, iv)
        bin = open(f_name + ".bin", "rb").read()
        f = open(f_name.split('.')[0], "wb")
        f.write(keyDecipher.decrypt(bin))
        f.close()

        # Running a Signature verification

        self.sigVerification(keyA_fname, f_name.split('.')[0])

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
                sys.exit(1)

            # Checking for public key's existence and access

            if not os.path.isfile(pubKey) or not os.access(pubKey, os.R_OK):
                print("Invalid public key file. Aborting...")
                sys.exit(6)

            # Checking for private key's existence and access

            if not os.path.isfile(priKey) or not os.access(priKey, os.R_OK):
                print("Invalid private key file. Aborting...")
                sys.exit(7)

        elif not first_run:
            # Checking if all of the necessary files exist and are accessible

            if not os.path.isfile(f_name + ".sig") or not os.access(f_name + ".sig", os.R_OK):
                print("Invalid *.sig file. Aborting...")
                sys.exit(2)
            if not os.path.isfile(f_name + ".key") or not os.access(f_name + ".key", os.R_OK):
                print("Invalid *.key file. Aborting...")
                sys.exit(3)
            if not os.path.isfile(f_name + ".bin") or not os.access(f_name + ".bin", os.R_OK):
                print("Invalid *.bin file. Aborting...")
                sys.exit(4)

            # Checking if in case of output file's existence, it is writable

            if os.path.isfile(f_name) and not os.access(f_name, os.W_OK):
                print("Can't create output file. Aborting...")
                sys.exit(5)


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):

        # initialize crypto classes
        self.decipher = Decipher()
        self.encipher = Enchipher()

        # generate the keys
        self.generate_keys()

        self._translate = QtCore.QCoreApplication.translate  # for translation   (whatever that is)

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

        self.textedit_io = QtWidgets.QLineEdit(self.centralWidget)    # OUTPUT or INPUT field
        self.textedit_io.setGeometry(QtCore.QRect(280, 100, 541, 321))
        self.textedit_io.setText("")
        self.textedit_io.setReadOnly(True)
        self.textedit_io.setObjectName("label")
        self.textedit_inputtext = ""
        self.textedit_outputtext = ""

        self.label_io = QtWidgets.QLabel(self.centralWidget)    # INPUT or OUTPUT, depending on state
        self.label_io.setGeometry(QtCore.QRect(510, 60, 81, 31))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_io.setFont(font)
        self.label_io.setObjectName("label_2")

        # RADIOBUTTONS FOR MODE SWITCHING

        self.radioButton_encrypt = QtWidgets.QRadioButton(self.centralWidget)
        self.radioButton_encrypt.setGeometry(QtCore.QRect(350, 30, 112, 23))
        self.radioButton_encrypt.setObjectName("radioButton")
        self.radioButton_encrypt.setEnabled(False)
        self.radioButton_encrypt.clicked.connect(lambda: self.switch_mode())  # switch to encryption layout

        self.radioButton_decrypt = QtWidgets.QRadioButton(self.centralWidget)
        self.radioButton_decrypt.setGeometry(QtCore.QRect(490, 30, 112, 23))
        self.radioButton_decrypt.setChecked(True)
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
        self.message_path = ""  # used to store path (idem for all others under this)

        # ENCRYPTED MESSAGE

        self.label_encryptedmessage_fp = QtWidgets.QLabel(self.centralWidget)
        self.label_encryptedmessage_fp.setGeometry(QtCore.QRect(50, 110, 151, 16))
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
        self.encrypted_msg_path = ""  # used to store path (idem for all others under this)

        # ENCRYPTED KEY

        self.label_encryptedkey_fp = QtWidgets.QLabel(self.centralWidget)
        self.label_encryptedkey_fp.setGeometry(QtCore.QRect(50, 160, 111, 16))
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
        self.label_encryptedhash_fp.setGeometry(QtCore.QRect(50, 210, 111, 16))
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
        self.label_publickey_fp.setGeometry(QtCore.QRect(50, 260, 81, 16))
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
        self.label_privatekey_fp.setGeometry(QtCore.QRect(50, 310, 81, 16))
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
        self.label_encryptedmessage_fp.setText(self._translate("MainWindow", "Encrypted message"))
        self.label_encryptedkey_fp.setText(self._translate("MainWindow", "Encrypted key"))
        self.label_encryptedhash_fp.setText(self._translate("MainWindow", "Encrypted hash"))
        self.label_publickey_fp.setText(self._translate("MainWindow", "Public key"))
        self.label_privatekey_fp.setText(self._translate("MainWindow", "Private key"))
        self.label_hashchecker.setText(self._translate("MainWindow", "Hashcheck ..."))

    def switch_mode(self):
        if self.radioButton_encrypt.isEnabled():
            self.mode = 1
        else:
            self.mode = 2

        if self.mode == 1:  # encryption
            self.radioButton_encrypt.setEnabled(False)
            self.radioButton_decrypt.setEnabled(True)

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

            self.message_filepicker_button.show()
            self.message_filepicker_result.show()
            self.label_message_fp.show()

            self.textedit_io.setText(self.textedit_inputtext)

        elif self.mode == 2:  # decryption
            self.radioButton_decrypt.setEnabled(False)
            self.radioButton_encrypt.setEnabled(True)

            self.label_io.setText(self._translate("MainWindow", "OUTPUT"))
            self.button_execute.setText(self._translate("MainWindow", "DECRYPT"))
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

            self.textedit_inputtext = self.textedit_io.text()
            self.textedit_io.setText(self.textedit_outputtext)

        self.button_active_check()

    def getfiles(self, type):
        """dlg = QtWidgets.QFileDialog()
        dlg.setFileMode(QtWidgets.QFileDialog.AnyFile)
        dlg.setFilter("Text files (*.txt)")"""
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

    # CHECK IF BUTTON SHOULD BE ACTIVE
    def button_active_check(self):
        if self.mode == 1:
            if not self.message_path == '':
                self.button_execute.setEnabled(True)
            else:
                self.button_execute.setEnabled(False)
        elif self.mode == 2:
            if not (self.encrypted_msg_path == '' or self.encrypted_key_path == '' or self.encrypted_hash_path == ''
                    or self.publickey_path == '' or self.privatekey_path == ''):
                self.button_execute.setEnabled(True)
            else:
                self.button_execute.setEnabled(False)

    def edit_text(self):
        self.textedit_inputtext = self.textedit_io.text()
        print(self.textedit_inputtext)

    # EXECUTE ENCRYPTION OR DECRYPTION
    def execution(self):
        print "HA"
        print self.message_filepicker_result.text(), self.message_path
        if self.mode == 1:
            self.encipher.encipher('files/priKeyA.pem', 'files/pubKeyB.pem', self.message_path)
            print "OK"
            self.encipher.auxFilesZip("files/" + self.message_filepicker_result.text().split('.')[0] + ".sig",
                                      "files/" + self.message_filepicker_result.text().split('.')[0] + ".key",
                                      "files/" + self.message_filepicker_result.text().split('.')[0] + ".bin")
            print "FILES MADE"
            # self.privatekey_sender =
            # encipher.encipher(self.message_path, self.)

    def generate_keys(self):

        keyPair = RSA.generate(1024)

        # For PrivateKey Generation

        f = open("files/priKeyA.pem", "w")
        f.write(keyPair.exportKey("PEM", "Basic Security_A"))
        f.close()

        # For PublicKey Generation

        f = open("files/pubKeyA.pem", "w")
        f.write(str(keyPair.publickey().exportKey()))
        f.close()

        keyPair = RSA.generate(1024)

        f = open("files/priKeyB.pem", "w")
        f.write(keyPair.exportKey("PEM", "Basic Security_B"))
        f.close()

        f = open("files/pubKeyB.pem", "w")
        f.write(str(keyPair.publickey().exportKey()))
        f.close()


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
