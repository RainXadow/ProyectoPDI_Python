import os
import tkinter as tk
from tkinter import filedialog
import shutil
import sys
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

def seleccion():
    print('1. Registrar usuario')
    print('2. Iniciar sesión')
    print('3. Listar usuarios')
    print('4. Salir')

    opcion = input('Selecciona una opción: ')

    if opcion == '1':
        registrar_usuario()
    elif opcion == '2':
        if iniciar_sesion():
            return True
    elif opcion == '3':
        listar_usuarios()
    elif opcion == '4':
        exit()
    else:
        print('Opción no válida. Por favor, selecciona una opción válida.')

# Definimos las funciones de registro e inicio de sesión
def registrar_usuario():
    username = input('Ingresa un nombre de usuario: ')
    password = input('Ingresa una contraseña: ')
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute('INSERT INTO usuarios (username, password) VALUES (?, ?)', (username, hashed_password))
    conn.commit()
    print('USUARIO REGISTRADO CON ÉXITO.\n')
    # Crear una carpeta con el nombre del usuario
    user_folder = f'usuarios/{username}'
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
        print(f'CARPETA DE USUARIO "{username}" CREADA CON ÉXITO.\n')
    else:
        print(f'La CARPETA DE USUARIO "{username}" YA EXISTE.\n')

def iniciar_sesion():
    username = input('Ingresa tu nombre de usuario: ')
    password = input('Ingresa tu contraseña: ')
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute('SELECT * FROM usuarios WHERE username=? AND password=?', (username, hashed_password))
    usuario = cursor.fetchone()
    if usuario:
        print(f'\nINICIO DE SESION EXITOSO PARA {username}\n')
        return True
    else:
        print('\nNOMBRE DE USUARIO O CONTRASEÑA INCORRECTOS. \n')
        return False

def listar_usuarios():
    cursor.execute('SELECT username FROM usuarios')
    usuarios = cursor.fetchall()
    print('Lista de usuarios:')
    for usuario in usuarios:
        print(usuario[0])
