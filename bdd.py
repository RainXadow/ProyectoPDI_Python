import os
import tkinter as tk
from tkinter import filedialog
import shutil
import sys
import sqlite3
import hashlib
import uuid
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode

nuevo_uuid = None

# Conexión a la base de datos
conn = sqlite3.connect('usuarios2.db')
cursor = conn.cursor()

# Creamos la tabla
cursor.execute('''
    CREATE TABLE IF NOT EXISTS usuarios (
        ID TEXT PRIMARY KEY,
        username TEXT,
        password TEXT,
        public_key TEXT,
        private_key TEXT
    )
''')

def generar_uuid128():
    new_uuid = uuid.uuid4()
    return str(new_uuid)

def generar_claves_rsa():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

def cifrar_clave_privada(clave_privada, password):
    salt = get_random_bytes(AES.block_size)
    private_key_salt = salt[:16]  # Usamos los primeros 16 bytes para el salt
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), private_key_salt, 100000)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(clave_privada)
    encrypted_private_key = b64encode(ciphertext + cipher.nonce + tag + private_key_salt).decode('utf-8')
    return encrypted_private_key

def seleccion():
    print('1. Registrar usuario')
    print('2. Iniciar sesión')
    print('3. Salir')

    opcion = input('Selecciona una opción: ')

    if opcion == '1':
        return registrar_usuario()
    elif opcion == '2':
        return iniciar_sesion()
    elif opcion == '3':
        exit()
    else:
        print('Opción no válida. Por favor, selecciona una opción válida.')

# Definimos las funciones de registro e inicio de sesión
def registrar_usuario():
    global nuevo_uuid
    username = input('Ingresa un nombre de usuario: ')
    password = input('Ingresa una contraseña: ')
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    public_key, private_key = generar_claves_rsa()
    encrypted_private_key = cifrar_clave_privada(private_key, password[:32])  # Utilizamos la primera mitad de la contraseña hash
    nuevo_uuid = generar_uuid128()
    cursor.execute('INSERT INTO usuarios (ID, username, password, public_key, private_key) VALUES (?, ?, ?, ?, ?)', (nuevo_uuid, username, hashed_password, public_key.decode('utf-8'), encrypted_private_key))
    conn.commit()
    print('USUARIO REGISTRADO CON ÉXITO.\n')
    # Crear una carpeta con el nombre del usuario
    user_folder = f'Servidor/{nuevo_uuid}'
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
        print(f'CARPETA DE USUARIO "{nuevo_uuid}" CREADA CON ÉXITO.\n')
        return 3
    else:
        print(f'La CARPETA DE USUARIO "{nuevo_uuid}" YA EXISTE.\n')
        return 3

def iniciar_sesion():
    username = input('Ingresa tu nombre de usuario: ')
    password = input('Ingresa tu contraseña: ')
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    cursor.execute('SELECT * FROM usuarios WHERE username=? AND password=?', (username, hashed_password))
    usuario = cursor.fetchone()

    if usuario:
        # Verificación adicional con la clave privada.
        encrypted_private_key = usuario[4]
        public_key = RSA.import_key(usuario[3])
        private_key_encrypted = b64decode(encrypted_private_key.encode('utf-8'))
        nonce = private_key_encrypted[16:32]  # Extraemos el nonce.
        tag = private_key_encrypted[-16:]  # Extraemos el tag.
        ciphertext = private_key_encrypted[:-32]  # El resto es el texto cifrado.

        # Preparamos el descifrador.
        cipher = PKCS1_OAEP.new(public_key)

        # Generamos un "reto" para que el cliente lo descifre.
        challenge = get_random_bytes(16)  # Un reto de 16 bytes.
        challenge_encrypted = cipher.encrypt(challenge)

        # Aquí, en una implementación real, enviaríamos el "reto" al cliente y esperaríamos la respuesta.
        # Como este script es una simulación y todo se ejecuta en el lado del cliente, simplemente continuamos.

        try:
            # El cliente debería hacer esto:
            # 1. Descifrar la clave privada con su contraseña.
            # 2. Descifrar el "reto" con su clave privada.
            # Desciframos la clave privada (esto se haría en el lado del cliente en un escenario real).
            salt = private_key_encrypted[-16:]
            key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
            cipher_aes = AES.new(key, AES.MODE_EAX, nonce=nonce)
            private_key_decrypted = cipher_aes.decrypt_and_verify(ciphertext, tag)

            # Desciframos el "reto" (también en el lado del cliente en la realidad).
            private_key = RSA.import_key(private_key_decrypted)
            cipher_rsa = PKCS1_OAEP.new(private_key)
            challenge_decrypted = cipher_rsa.decrypt(challenge_encrypted)

            if challenge_decrypted == challenge:
                # El reto se descifró correctamente, así que el usuario está autenticado.
                print(f'\nINICIO DE SESION EXITOSO PARA {username}\n')
                # ... Resto del código de manejo de sesión ...
            else:
                print('\nFALLO EN LA VERIFICACION DE LA CLAVE PRIVADA.\n')
                return 2
        except Exception as e:
            print('\nFALLO EN LA VERIFICACION DE LA CLAVE PRIVADA.\n')
            return 2
    else:
        print('\nNOMBRE DE USUARIO O CONTRASEÑA INCORRECTOS. \n')
        return 2

# Inicio del programa
if __name__ == "__main__":
    while True:
        seleccion()
