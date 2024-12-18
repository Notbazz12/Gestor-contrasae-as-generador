import sqlite3
import csv
import random
import string
import hashlib
from cryptography.fernet import Fernet
import base64

# Clave de encriptación (deberías almacenar esto de forma segura, no en el código)
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

def encrypt(data):
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt(data):
    return cipher_suite.decrypt(data.encode()).decode()

def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except sqlite3.Error as e:
        print(e)
    return conn

def create_table(conn):
    try:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS passwords
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      service TEXT NOT NULL,
                      username TEXT NOT NULL,
                      password TEXT NOT NULL,
                      category TEXT)''')
    except sqlite3.Error as e:
        print(e)

def add_password(conn, service, username, password, category):
    encrypted_password = encrypt(password)
    sql = ''' INSERT INTO passwords(service,username,password,category)
              VALUES(?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, (service, username, encrypted_password, category))
    conn.commit()
    return cur.lastrowid

def get_password(conn, service, username):
    cur = conn.cursor()
    cur.execute("SELECT password FROM passwords WHERE service=? AND username=?", (service, username))
    result = cur.fetchone()
    if result:
        encrypted_password = result[0]
        decrypted_password = decrypt(encrypted_password)
        return decrypted_password
    return None

def search_passwords(conn, search_term):
    cur = conn.cursor()
    cur.execute("SELECT service, username, category FROM passwords WHERE service LIKE ? OR username LIKE ? OR category LIKE ?", 
                ('%'+search_term+'%', '%'+search_term+'%', '%'+search_term+'%'))
    return cur.fetchall()

def update_password(conn, service, username, new_password):
    encrypted_password = encrypt(new_password)
    sql = ''' UPDATE passwords
              SET password = ?
              WHERE service = ? AND username = ?'''
    cur = conn.cursor()
    cur.execute(sql, (encrypted_password, service, username))
    conn.commit()
    return cur.rowcount > 0

def delete_password(conn, service, username):
    sql = 'DELETE FROM passwords WHERE service=? AND username=?'
    cur = conn.cursor()
    cur.execute(sql, (service, username))
    conn.commit()
    return cur.rowcount > 0

def generate_password(length=20, use_uppercase=True, use_lowercase=True, use_digits=True, use_symbols=True):
    characters = ""
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_digits:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation

    if not characters:
        raise ValueError("Al menos un conjunto de caracteres debe ser seleccionado")

    return ''.join(random.choice(characters) for _ in range(length))

def export_passwords(conn, filename):
    cur = conn.cursor()
    cur.execute("SELECT * FROM passwords")
    rows = cur.fetchall()
    
    with open(filename, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["ID", "Service", "Username", "Password", "Category"])  # Encabezados
        for row in rows:
            decrypted_row = list(row)
            decrypted_row[3] = decrypt(row[3])  # Desencriptar la contraseña
            writer.writerow(decrypted_row)

def import_passwords(conn, filename):
    with open(filename, 'r') as file:
        csv_reader = csv.reader(file)
        next(csv_reader)  # Saltar la fila de encabezados
        for row in csv_reader:
            add_password(conn, row[1], row[2], row[3], row[4])

def verify_master_password(password, stored_hash):
    return hashlib.sha256(password.encode()).hexdigest() == stored_hash