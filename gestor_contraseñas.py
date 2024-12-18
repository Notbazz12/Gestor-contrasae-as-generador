import database
import hashlib
import os
import sys
import random
import string
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit,
                             QLabel, QMessageBox, QInputDialog, QFileDialog, QListWidget, QToolBar, QAction, QFrame, QDialog, QTabWidget)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt

MASTER_PASSWORD_FILE = "master_password.hash"
SECURE_FILE_STORAGE = "secure_files"

def derive_key(password: str) -> bytes:
    """Derive a key from the master password."""
    return hashlib.sha256(password.encode()).digest()

def encrypt_file(file_path: str, key: bytes):
    """Encrypt a file using the provided key."""
    with open(file_path, 'rb') as file:
        data = file.read()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    with open(file_path, 'wb') as file:
        file.write(encrypted)

def decrypt_file(file_path: str, key: bytes):
    """Decrypt a file using the provided key."""
    with open(file_path, 'rb') as file:
        data = file.read()
    fernet = Fernet(key)
    decrypted = fernet.decrypt(data)
    with open(file_path, 'wb') as file:
        file.write(decrypted)

class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Gestor de Contraseñas - Inicio de Sesión")
        self.setFixedSize(300, 150)
        layout = QVBoxLayout()

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Ingrese la contraseña maestra")
        layout.addWidget(self.password_input)

        login_button = QPushButton("Iniciar Sesión")
        login_button.clicked.connect(self.accept)
        layout.addWidget(login_button)

        self.setLayout(layout)

class PasswordManagerGUI(QMainWindow):
    def __init__(self, master_password):
        super().__init__()
        self.conn = database.create_connection("contraseñas.db")
        database.create_table(self.conn)
        self.key = derive_key(master_password)
        if not os.path.exists(SECURE_FILE_STORAGE):
            os.makedirs(SECURE_FILE_STORAGE)
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Gestor de Contraseñas')
        self.setGeometry(100, 100, 800, 600)

        toolbar = QToolBar()
        self.addToolBar(toolbar)

        add_action = QAction(QIcon('add_icon.png'), 'Agregar', self)
        add_action.triggered.connect(self.show_add_password)
        toolbar.addAction(add_action)

        generate_action = QAction(QIcon('generate_icon.png'), 'Generar', self)
        generate_action.triggered.connect(self.generate_password)
        toolbar.addAction(generate_action)

        export_action = QAction(QIcon('export_icon.png'), 'Exportar', self)
        export_action.triggered.connect(self.export_passwords)
        toolbar.addAction(export_action)

        import_action = QAction(QIcon('import_icon.png'), 'Importar', self)
        import_action.triggered.connect(self.import_passwords)
        toolbar.addAction(import_action)

        # Add a search bar
        search_input = QLineEdit()
        search_input.setPlaceholderText("Buscar...")
        search_input.textChanged.connect(self.search_items)
        toolbar.addWidget(search_input)

        central_widget = QTabWidget()
        self.setCentralWidget(central_widget)

        main_widget = QWidget()
        main_layout = QHBoxLayout(main_widget)

        self.item_list = QListWidget()
        self.item_list.itemClicked.connect(self.show_item_details)
        main_layout.addWidget(self.item_list, 1)

        line = QFrame()
        line.setFrameShape(QFrame.VLine)
        line.setFrameShadow(QFrame.Sunken)
        main_layout.addWidget(line)

        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        main_layout.addWidget(details_widget, 2)

        self.service_input = QLineEdit()
        self.service_input.setPlaceholderText("Servicio")
        details_layout.addWidget(self.service_input)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Usuario")
        details_layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Contraseña")
        self.password_input.setEchoMode(QLineEdit.Password)
        details_layout.addWidget(self.password_input)

        copy_button = QPushButton("Copiar Contraseña")
        copy_button.clicked.connect(self.copy_password_to_clipboard)
        details_layout.addWidget(copy_button)

        self.category_input = QLineEdit()
        self.category_input.setPlaceholderText("Categoría (opcional)")
        details_layout.addWidget(self.category_input)

        button_layout = QHBoxLayout()
        save_button = QPushButton("Guardar")
        save_button.clicked.connect(self.save_item)
        button_layout.addWidget(save_button)

        delete_button = QPushButton("Eliminar")
        delete_button.clicked.connect(self.delete_item)
        button_layout.addWidget(delete_button)

        details_layout.addLayout(button_layout)

        central_widget.addTab(main_widget, "Gestión de Contraseñas")

        self.load_items()

    def load_items(self):
        self.item_list.clear()
        items = database.search_passwords(self.conn, "")
        for item in items:
            self.item_list.addItem(f"{item[0]} - {item[1]}")

    def search_items(self, text):
        self.item_list.clear()
        items = database.search_passwords(self.conn, text)
        for item in items:
            self.item_list.addItem(f"{item[0]} - {item[1]}")

    def show_item_details(self, item):
        service, username = item.text().split(" - ")
        password = database.get_password(self.conn, service, username)
        if password:
            self.service_input.setText(service)
            self.username_input.setText(username)
            self.password_input.setText(password)
            self.category_input.setText("")

    def show_add_password(self):
        self.clear_inputs()
        self.service_input.setFocus()

    def save_item(self):
        service = self.service_input.text()
        username = self.username_input.text()
        password = self.password_input.text()
        category = self.category_input.text() or "General"

        if service and username and password:
            if len(password) < 20:
                QMessageBox.warning(self, "Error", "La contraseña debe tener al menos 20 caracteres.")
                return
            database.add_password(self.conn, service, username, password, category)
            QMessageBox.information(self, "Éxito", "Contraseña guardada exitosamente!")
            self.load_items()
            self.clear_inputs()
        else:
            QMessageBox.warning(self, "Error", "Por favor, complete todos los campos.")

    def delete_item(self):
        service = self.service_input.text()
        username = self.username_input.text()
        if service and username:
            if database.delete_password(self.conn, service, username):
                QMessageBox.information(self, "Éxito", "Entrada eliminada.")
                self.load_items()
                self.clear_inputs()
            else:
                QMessageBox.warning(self, "Error", "No se pudo eliminar la entrada.")
        else:
            QMessageBox.warning(self, "Error", "Por favor, seleccione una entrada para eliminar.")

    def clear_inputs(self):
        self.service_input.clear()
        self.username_input.clear()
        self.password_input.clear()
        self.category_input.clear()

    def generate_password(self):
        length = 20
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for i in range(length))
        self.password_input.setText(password)

    def copy_password_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.password_input.text())
        QMessageBox.information(self, "Éxito", "Contraseña copiada al portapapeles.")

    def export_passwords(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Exportar Contraseñas", "", "CSV Files (*.csv)")
        if filename:
            database.export_passwords(self.conn, filename)
            encrypt_file(filename, self.key)
            QMessageBox.information(self, "Éxito", "Contraseñas exportadas y cifradas exitosamente!")

    def import_passwords(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Importar Contraseñas", "", "CSV Files (*.csv)")
        if filename:
            decrypt_file(filename, self.key)
            database.import_passwords(self.conn, filename)
            self.load_items()
            QMessageBox.information(self, "Éxito", "Contraseñas importadas exitosamente!")

def main():
    app = QApplication(sys.argv)

    if not os.path.exists(MASTER_PASSWORD_FILE):
        password, ok = QInputDialog.getText(None, "Configuración inicial", "Establezca la contraseña maestra:", QLineEdit.Password)
        if ok:
            with open(MASTER_PASSWORD_FILE, "w") as f:
                f.write(hashlib.sha256(password.encode()).hexdigest())
        else:
            return

    login = LoginDialog()
    if login.exec_() == QDialog.Accepted:
        with open(MASTER_PASSWORD_FILE, "r") as f:
            stored_hash = f.read().strip()

        if database.verify_master_password(login.password_input.text(), stored_hash):
            window = PasswordManagerGUI(login.password_input.text())
            window.show()
            sys.exit(app.exec_())
        else:
            QMessageBox.critical(None, "Error", "Contraseña incorrecta.")

if __name__ == '__main__':
    main()