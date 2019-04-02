# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'mainwindow.ui'
#
# Created by: PyQt5 UI code generator 5.10.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        self._translate = QtCore.QCoreApplication.translate  # for translation   (whatever that is)

        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(914, 560)

        self.centralWidget = QtWidgets.QWidget(MainWindow)
        self.centralWidget.setObjectName("centralWidget")

        # BUTTON FOR EXECUTING CODE BEHIND

        self.button_execute = QtWidgets.QPushButton(self.centralWidget)  # button to DECRYPT or ENCRYPT
        self.button_execute.setEnabled(False)  # depending on state
        self.button_execute.setGeometry(QtCore.QRect(50, 410, 111, 51))  # still need to connect function
        self.button_execute.setMaximumSize(QtCore.QSize(111, 16777215))
        self.button_execute.setObjectName("decryptButton")

        self.label = QtWidgets.QLabel(self.centralWidget)  # OUTPUT field, remindme better TextEdit
        self.label.setGeometry(QtCore.QRect(280, 100, 541, 321))
        self.label.setText("")
        self.label.setObjectName("label")

        self.label_io = QtWidgets.QLabel(self.centralWidget)  # INPUT or OUTPUT, depending on state
        self.label_io.setGeometry(QtCore.QRect(510, 60, 81, 31))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_io.setFont(font)
        self.label_io.setObjectName("label_2")

        # RADIOBUTTONS FOR MODE SWITCHING

        self.radioButton_encrypt = QtWidgets.QRadioButton(self.centralWidget)
        self.radioButton_encrypt.setGeometry(QtCore.QRect(350, 30, 112, 23))
        self.radioButton_encrypt.setObjectName("radioButton")
        self.radioButton_encrypt.clicked.connect(lambda: self.switch_mode(1))  # switch to encryption layout

        self.radioButton_decrypt = QtWidgets.QRadioButton(self.centralWidget)
        self.radioButton_decrypt.setGeometry(QtCore.QRect(490, 30, 112, 23))
        self.radioButton_decrypt.setChecked(True)
        self.radioButton_decrypt.setObjectName("radioButton_2")
        self.radioButton_decrypt.clicked.connect(lambda: self.switch_mode(2))  # switch to decryption layout

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

        self.menuBar = QtWidgets.QMenuBar(MainWindow)
        self.menuBar.setGeometry(QtCore.QRect(0, 0, 914, 22))
        self.menuBar.setObjectName("menuBar")
        MainWindow.setMenuBar(self.menuBar)

        self.mainToolBar = QtWidgets.QToolBar(MainWindow)
        self.mainToolBar.setObjectName("mainToolBar")
        MainWindow.addToolBar(QtCore.Qt.TopToolBarArea, self.mainToolBar)
        self.statusBar = QtWidgets.QStatusBar(MainWindow)

        self.statusBar.setObjectName("statusBar")
        MainWindow.setStatusBar(self.statusBar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(self._translate("MainWindow", "Basic Security"))
        self.button_execute.setText(self._translate("MainWindow", "DECRYPT"))
        self.label_io.setText(self._translate("MainWindow", "OUTPUT"))
        self.radioButton_encrypt.setText(self._translate("MainWindow", "ENCRYPT"))
        self.radioButton_decrypt.setText(self._translate("MainWindow", "DECRYPT"))
        self.label_encryptedmessage_fp.setText(self._translate("MainWindow", "Encrypted message"))
        self.label_encryptedkey_fp.setText(self._translate("MainWindow", "Encrypted key"))
        self.label_encryptedhash_fp.setText(self._translate("MainWindow", "Encrypted hash"))
        self.label_publickey_fp.setText(self._translate("MainWindow", "Public key"))
        self.label_privatekey_fp.setText(self._translate("MainWindow", "Private key"))
        self.label_hashchecker.setText(self._translate("MainWindow", "Hashcheck ..."))

    def switch_mode(self, mode):
        if mode == 1:  # encryption
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

        elif mode == 2:  # decryption
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
        self.button_active_check(mode)

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

        self.button_active_check(2)

    def button_active_check(self, mode):
        if mode == 1:
            self.button_execute.setEnabled(False)
        elif mode == 2:
            if not (self.encrypted_msg_path == '' or self.encrypted_key_path == '' or self.encrypted_hash_path == ''
                    or self.publickey_path == '' or self.privatekey_path == ''):
                self.button_execute.setEnabled(True)
            else:
                self.button_execute.setEnabled(False)


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
