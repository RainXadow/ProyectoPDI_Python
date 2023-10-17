import os
import tkinter as tk
from tkinter import filedialog
import shutil
import sqlite3
import hashlib

# Conexión a la base de datos
conn = sqlite3.connect('usuarios.db')
cursor = conn.cursor()

# Creamos la tabla 
cursor.execute('''
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT
    )
''')
#Definimos las funciones de registro e inicio de sesion
def registrar_usuario():
    username = input('Ingresa un nombre de usuario: ')
    password = input('Ingresa una contraseña: ')
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute('INSERT INTO usuarios (username, password) VALUES (?, ?)', (username, hashed_password))
    conn.commit()
    print('USUARIO REGISTRADO EXITOSAMENTE.')

def iniciar_sesion():
    username = input('Ingresa tu nombre de usuario: ')
    password = input('Ingresa tu contraseña: ')
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute('SELECT * FROM usuarios WHERE username=? AND password=?', (username, hashed_password))
    usuario = cursor.fetchone()
    if usuario:
        print(f'INICIO DE SESION EXITOSO PARA {username}')
    else:
        print('NOMBRE DE USUARIO O CONTRASEÑA INCORRECTOS.')

        
def listar_usuarios():
    cursor.execute('SELECT username FROM usuarios')
    usuarios = cursor.fetchall()
    print('Lista de usuarios:')
    for usuario in usuarios:
        print(usuario[0])
while True:
    print('1. Registrar usuario')
    print('2. Iniciar sesión')
    print('3. Listar usuarios')
    print('4. Salir')

    opcion = input('Selecciona una opción: ')

    if opcion == '1':
        registrar_usuario()
    elif opcion == '2':
        iniciar_sesion()
    elif opcion == '3':
        listar_usuarios()
    elif opcion == '4':
        break
    else:
        print('Opción no válida. Por favor, selecciona una opción válida.')