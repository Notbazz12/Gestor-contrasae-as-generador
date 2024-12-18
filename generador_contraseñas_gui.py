import sys
import random
import string
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox, QSpinBox

class PasswordGeneratorGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Generador de Contraseñas')
        self.setGeometry(100, 100, 300, 200)

        layout = QVBoxLayout()

        self.length_label = QLabel('Longitud de la contraseña:')
        layout.addWidget(self.length_label)

        self.length_input = QSpinBox()
        self.length_input.setMinimum(20)
        self.length_input.setValue(20)
        layout.addWidget(self.length_input)

        self.generate_button = QPushButton('Generar Contraseña')
        self.generate_button.clicked.connect(self.generate_password)
        layout.addWidget(self.generate_button)

        self.password_output = QLineEdit()
        self.password_output.setReadOnly(True)
        layout.addWidget(self.password_output)

        self.setLayout(layout)

    def generate_password(self):
        length = self.length_input.value()
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(length))
        self.password_output.setText(password)
        QMessageBox.information(self, "Éxito", "Contraseña generada exitosamente!")

def main():
    app = QApplication(sys.argv)
    window = PasswordGeneratorGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()