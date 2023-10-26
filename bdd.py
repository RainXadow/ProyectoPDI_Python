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

# Establece la conexión con una base de datos SQLite y crea una tabla 'usuarios' si no existe.
conn = sqlite3.connect('usuarios2.db')
cursor = conn.cursor()

# Crea la tabla 'usuarios' en la base de datos con campos para ID, nombre de usuario, contraseña, clave pública y clave privada.
cursor.execute('''
    CREATE TABLE IF NOT EXISTS usuarios (
        ID TEXT PRIMARY KEY,
        username TEXT,
        password TEXT,
        public_key TEXT
    )
''')


def generar_uuid128():
    """
    Genera un UUID (Identificador Único Universal) versión 4, que se usa como un identificador único para cada usuario.
    """
    new_uuid = uuid.uuid4()
    return str(new_uuid)

def generar_claves_rsa():
    """
    Genera un par de claves RSA (una clave pública y una clave privada) para el cifrado.
    Devuelve ambas claves.
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

def guardar_clave_privada_en_archivo(encrypted_private_key, uuid):
    """
    Guarda la clave privada cifrada en un archivo en el disco local.
    """
    file_path = f"{uuid}_private_key.txt"
    with open(file_path, 'w') as file:
        file.write(encrypted_private_key)
    print(f"Clave privada almacenada en: {file_path}")
    
def seleccionar_archivo_clave_privada():
    """
    Abre un diálogo para que el usuario seleccione un archivo de clave privada cifrada.
    Devuelve la ruta del archivo seleccionado.
    """
    root = tk.Tk()
    root.withdraw()  # No queremos una ventana completa de Tk, solo el diálogo
    file_path = filedialog.askopenfilename()
    return file_path

def cifrar_clave_privada(clave_privada, password):
    """
    Cifra la clave privada RSA de un usuario utilizando AES.

    Args:
    - clave_privada: La clave privada RSA a cifrar.
    - password: La contraseña del usuario, que se usa para generar una clave AES.

    Devuelve la clave privada cifrada en formato de cadena codificada en base64.
    """
    salt = get_random_bytes(AES.block_size)
    private_key_salt = salt[:16]  # Usamos los primeros 16 bytes para el salt
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), private_key_salt, 100000)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(clave_privada)
    encrypted_private_key = b64encode(ciphertext + cipher.nonce + tag + private_key_salt).decode('utf-8')
    return encrypted_private_key

def seleccion():
    """
    Muestra un menú de selección al usuario y ejecuta la función correspondiente a la elección del usuario.
    """
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
    """
    Registra un nuevo usuario en la base de datos.
    El usuario proporciona un nombre de usuario y una contraseña.
    Se genera un UUID para el usuario y se cifra su clave privada RSA con la contraseña.
    La información del usuario se almacena en la base de datos.
    """
    global nuevo_uuid
    username = input('Ingresa un nombre de usuario: ')
    password = input('Ingresa una contraseña: ')
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    public_key, private_key = generar_claves_rsa()
    encrypted_private_key = cifrar_clave_privada(private_key, password[:32])  # Utilizamos la primera mitad de la contraseña hash
    nuevo_uuid = generar_uuid128()
    # Guardar la clave privada en un archivo en lugar de en la base de datos.
    guardar_clave_privada_en_archivo(encrypted_private_key, nuevo_uuid)
    cursor.execute('INSERT INTO usuarios (ID, username, password, public_key) VALUES (?, ?, ?, ?)', 
                   (nuevo_uuid, username, hashed_password, public_key.decode('utf-8')))
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
    """
    Permite a un usuario iniciar sesión verificando su nombre de usuario y contraseña.
    Adicionalmente, realiza una verificación de dos pasos utilizando un "reto" cifrado con la clave privada del usuario,
    que debe ser descifrado correctamente para completar la autenticación.
    """
    username = input('Ingresa tu nombre de usuario: ')
    password = input('Ingresa tu contraseña: ')
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    cursor.execute('SELECT * FROM usuarios WHERE username=? AND password=?', (username, hashed_password))
    usuario = cursor.fetchone()

    if usuario:
        file_path = seleccionar_archivo_clave_privada()
        if not file_path:
            print("\nNo se seleccionó ningún archivo.\n")
            return 3

        with open(file_path, 'r') as file:
            encrypted_private_key = file.read()
        
        public_key = RSA.import_key(usuario[3])
        private_key_encrypted = b64decode(encrypted_private_key.encode('utf-8'))
        
        # Asumiendo que el tamaño de nonce, tag y salt son 16 bytes cada uno
        nonce_size = 16
        tag_size = 16
        salt_size = 16
        
        # Calculamos la posición donde empieza cada elemento
        nonce_start = len(private_key_encrypted) - nonce_size - tag_size - salt_size
        tag_start = len(private_key_encrypted) - tag_size - salt_size
        salt_start = len(private_key_encrypted) - salt_size
        
        
         # Extraemos el nonce, tag y salt
        nonce = private_key_encrypted[nonce_start:tag_start]
        tag = private_key_encrypted[tag_start:salt_start]
        salt = private_key_encrypted[salt_start:]

        # El ciphertext es todo lo demás
        ciphertext = private_key_encrypted[:nonce_start]

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
                return 1
            else:
                print('\nFALLO EN LA VERIFICACION DE LA CLAVE PRIVADA.\n')
                return 3
        except Exception as e:
            print(f'Error: {e}')
            return 3
    else:
        print('\nNOMBRE DE USUARIO O CONTRASEÑA INCORRECTOS. \n')
        return 2

# Inicio del programa
if __name__ == "__main__":
    while True:
        seleccion()
