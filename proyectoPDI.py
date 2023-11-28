import json
import os
import shutil
import sqlite3
import sys
import tkinter as tk
from tkinter import filedialog

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

import bdd
from bdd import (cifrar_con_aes, descifrar_con_aes, iniciar_sesion,
                 registrar_usuario, seleccion)

user_id=None
def autenticar_usuario():
    resultado = iniciar_sesion()
    if resultado == 1:
        return True
    return False

def listar_archivos_usuario(user_id):
    carpeta_usuario = f'Servidor/{user_id}'
    if not os.path.exists(carpeta_usuario):
        print("No hay archivos disponibles.")
        return []

    elementos = []  # Lista para almacenar tanto archivos como carpetas
    for raiz, carpetas, archivos in os.walk(carpeta_usuario):
        for carpeta in carpetas:
            ruta_completa = os.path.join(raiz, carpeta)
            ruta_relativa = os.path.relpath(ruta_completa, carpeta_usuario)
            elementos.append(ruta_relativa)

        for archivo in archivos:
            ruta_completa = os.path.join(raiz, archivo)
            ruta_relativa = os.path.relpath(ruta_completa, carpeta_usuario)
            elementos.append(ruta_relativa)

    print("Elementos disponibles:")
    for idx, elemento in enumerate(elementos):
        print(f"{idx + 1}. {elemento}")

    return elementos

def obtener_clave_aes_cifrada_de_db(user_id, nombre_archivo):
    conn = sqlite3.connect('usuarios2.db')
    cursor = conn.cursor()
    cursor.execute('SELECT clave_AES_cifrada FROM archivos WHERE user_id=? AND nombre_archivo=?',
                   (user_id, nombre_archivo))
    clave_aes_cifrada = cursor.fetchone()[0]
    conn.close()
    return clave_aes_cifrada

def descifrar_clave_aes_con_rsa(user_id, clave_aes_cifrada):
    clave_privada_rsa = bdd.seleccionar_archivo_clave_privada()
        
    clave_privada = RSA.import_key(clave_privada_rsa)
    cipher_rsa = PKCS1_OAEP.new(clave_privada)
    clave_aes = cipher_rsa.decrypt(clave_aes_cifrada)
    return clave_aes

# Descargamos y desciframos
def descargar_y_descifrar_archivo():
    # Cargar el user_id del archivo session_data.json
    with open('session_data.json', 'r') as file:
        session_data = json.load(file)
    user_id = session_data.get('user_uuid')

    elementos = listar_archivos_usuario(user_id)
    if not elementos:
        return

    eleccion = input("Ingrese los números de los elementos a descargar, separados por comas: ")
    indices_seleccionados = [int(x.strip()) - 1 for x in eleccion.split(',') if x.strip().isdigit()]

    for idx in indices_seleccionados:
        if 0 <= idx < len(elementos):
            elemento = elementos[idx]
            ruta_elemento = os.path.join(f'Servidor/{user_id}', elemento)

            if os.path.isfile(ruta_elemento):
                # Descifrar y descargar archivo
                descargar_y_descifrar_archivo_individual(user_id, ruta_elemento)
            elif os.path.isdir(ruta_elemento):
                # Descifrar y descargar carpeta
                descargar_y_descifrar_carpeta(user_id, ruta_elemento)
            else:
                print(f"Elemento {elemento} no encontrado.")
        else:
            print(f"Índice {idx + 1} no válido.")
            
def descargar_y_descifrar_archivo_individual(user_id, ruta_archivo_cifrado):
    # Leer el archivo cifrado
    with open(ruta_archivo_cifrado, 'rb') as f:
        datos_cifrados = f.read()

    # Obtener la clave AES cifrada de la base de datos
    clave_aes_cifrada = obtener_clave_aes_cifrada_de_db(user_id, os.path.basename(ruta_archivo_cifrado))

    # Descifrar la clave AES
    clave_aes = descifrar_clave_aes_con_rsa(user_id, clave_aes_cifrada)

    # Descifrar el archivo
    try:
        datos_descifrados = descifrar_con_aes(user_id, datos_cifrados)

        # Guardar el archivo descifrado
        ruta_archivo_descifrado = os.path.join("Descargas", os.path.basename(ruta_archivo_cifrado).replace('.aes', ''))
        os.makedirs(os.path.dirname(ruta_archivo_descifrado), exist_ok=True)
        with open(ruta_archivo_descifrado, 'wb') as f:
            f.write(datos_descifrados)

        print(f"Archivo {os.path.basename(ruta_archivo_cifrado)} descargado y descifrado.")
    except Exception as e:
        print(f"Error al descifrar {os.path.basename(ruta_archivo_cifrado)}: {e}")
        
def descargar_y_descifrar_carpeta(user_id, ruta_carpeta_cifrada):
    nombre_carpeta = os.path.basename(ruta_carpeta_cifrada)
    carpeta_destino = os.path.join("Descargas", nombre_carpeta)

    for raiz, _, archivos in os.walk(ruta_carpeta_cifrada):
        for nombre_archivo in archivos:
            ruta_archivo_cifrado = os.path.join(raiz, nombre_archivo)

            # Calcular la ruta relativa y la ruta de destino descifrada
            ruta_relativa_cifrada = os.path.relpath(ruta_archivo_cifrado, ruta_carpeta_cifrada)
            ruta_archivo_descifrado = os.path.join(carpeta_destino, ruta_relativa_cifrada)
            ruta_archivo_descifrado = ruta_archivo_descifrado.replace('.aes', '')
            os.makedirs(os.path.dirname(ruta_archivo_descifrado), exist_ok=True)

            # Leer y descifrar el archivo
            with open(ruta_archivo_cifrado, 'rb') as f:
                datos_cifrados = f.read()

            try:
                datos_descifrados = descifrar_con_aes(user_id, datos_cifrados)

                with open(ruta_archivo_descifrado, 'wb') as f:
                    f.write(datos_descifrados)

                print(f"Archivo {nombre_archivo} descargado y descifrado en {ruta_archivo_descifrado}.")
            except Exception as e:
                print(f"Error al descifrar {nombre_archivo}: {e}")
                
def guardar_archivo_y_clave_en_db(user_id, nombre_archivo, clave_aes_cifrada):
    conn = sqlite3.connect('usuarios2.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO archivos (user_id, nombre_archivo, clave_AES_cifrada) VALUES (?, ?, ?)',
                   (user_id, nombre_archivo, clave_aes_cifrada))
    conn.commit()
    conn.close()

# Ciframos el archivo y lo subimos
def subir_archivo():
    # Cargar el user_id del archivo session_data.json
    with open('session_data.json', 'r') as file:
        session_data = json.load(file)
    user_id = session_data.get('user_uuid')
    
    # Solicitar al usuario que seleccione los archivos
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True) # Nos aseguramos de que esté en primer plano
    archivos = filedialog.askopenfilenames()
    root.attributes('-topmost', False) # Desactivmos el primer plano
    root.destroy()

    # Verificar si se seleccionaron archivos
    if not archivos:
        print("No se seleccionó ningún archivo.")
        return

    for archivo in archivos:
        with open(archivo, 'rb') as f:
            datos_archivo = f.read()

        # Cifrar el archivo con una clave AES aleatoria y obtener la clave AES cifrada con RSA
        nonce, tag, datos_cifrados, clave_aes_cifrada = cifrar_con_aes(user_id, datos_archivo)

        # Guardar el archivo cifrado y la clave cifrada en la base de datos
        nombre_archivo_cifrado = os.path.basename(archivo) + '.aes'
        guardar_archivo_y_clave_en_db(user_id, nombre_archivo_cifrado, clave_aes_cifrada)

    print(f"{len(archivos)} archivo(s) subido(s) y cifrado(s) con éxito.")


def subir_carpeta():
    # Cargar el user_id del archivo session_data.json
    with open('session_data.json', 'r') as file:
        session_data = json.load(file)
    user_id = session_data.get('user_uuid')

    # Carpeta de destino en el servidor
    carpeta_destino = f'Servidor/{user_id}'

    # Solicitar al usuario que seleccione la carpeta
    root = tk.Tk()
    root.withdraw()
    carpeta_seleccionada = filedialog.askdirectory()
    root.destroy()

    if not carpeta_seleccionada:
        print("No se seleccionó una carpeta.")
        return

    carpeta_nombre = os.path.basename(carpeta_seleccionada)
    carpeta_destino_final = os.path.join(carpeta_destino, carpeta_nombre)

    if os.path.exists(carpeta_destino_final):
        print(f"La carpeta '{carpeta_nombre}' ya existe en el destino.")
        return

    os.makedirs(carpeta_destino_final)

    # Cifrar y copiar cada archivo en la carpeta seleccionada
    for raiz, _, archivos in os.walk(carpeta_seleccionada):
        for nombre_archivo in archivos:
            ruta_archivo = os.path.join(raiz, nombre_archivo)

            # Leer y cifrar el archivo
            with open(ruta_archivo, 'rb') as f:
                datos_archivo = f.read()
            nonce, tag, datos_cifrados = cifrar_con_aes(user_id, datos_archivo)

            # Ruta relativa para preservar la estructura de carpetas
            ruta_relativa = os.path.relpath(ruta_archivo, carpeta_seleccionada)
            ruta_destino = os.path.join(carpeta_destino_final, ruta_relativa) + '.aes'

            os.makedirs(os.path.dirname(ruta_destino), exist_ok=True)
            with open(ruta_destino, 'wb') as f:
                f.write(nonce)
                f.write(tag)
                f.write(datos_cifrados)

    print(f"Carpeta '{carpeta_nombre}' subida y cifrada con éxito.")




'''
def subir_carpeta():
    """
    Solicita al usuario que seleccione una carpeta y la copia a una carpeta
    en el servidor basada en el user_id obtenido de session_data.json.
    """
    # Cargar el user_id del archivo session_data.json
    with open('session_data.json', 'r') as file:
        session_data = json.load(file)
    user_id = session_data.get('user_uuid')

    # Carpeta base de destino en el servidor
    carpeta_base_destino = os.path.normpath(f'Servidor/{user_id}')

    # Solicitar al usuario que seleccione la carpeta
    root = tk.Tk()
    root.withdraw()
    carpeta_seleccionada = filedialog.askdirectory()
    root.destroy()

    # Verificar que el usuario haya seleccionado una carpeta
    if not carpeta_seleccionada:
        print("No se seleccionó ninguna carpeta.")
        return

    carpeta_seleccionada = os.path.normpath(carpeta_seleccionada)
    nombre_carpeta_origen = os.path.basename(carpeta_seleccionada)
    carpeta_destino = os.path.join(carpeta_base_destino, nombre_carpeta_origen)

    if not os.path.exists(carpeta_destino):
        os.makedirs(carpeta_destino)

    for dirpath, dirnames, filenames in os.walk(carpeta_seleccionada):
        destino = os.path.join(carpeta_destino, os.path.relpath(dirpath, carpeta_seleccionada))
        destino = os.path.normpath(destino)

        if not os.path.exists(destino):
            os.makedirs(destino)

        for filename in filenames:
            archivo_origen = os.path.join(dirpath, filename)
            archivo_destino = os.path.join(destino, filename)

            print(f"Copiando de {archivo_origen} a {archivo_destino}")  # Agregar impresión para depuración
            shutil.copy(archivo_origen, archivo_destino)
            
'''

def gestionar_drive():
    global user_id
    # Cargar la variable de sesión desde el archivo JSON
    with open('session_data.json', 'r') as file:
            session = json.load(file)
    user_id= session.get('user_uuid')
    print({user_id})
    drive_folder = f'Servidor/{user_id}'
    print({drive_folder})
    if not os.path.exists(drive_folder):
         os.mkdir(drive_folder)
    while True:
        print("\nMenú de opciones:")
        print("1. Crear archivo")
        print("2. Crear carpeta")
        print("3. Subir archivo")
        print("4. Subir carpeta")
        print("5. Descargar archivos")
        print("6. Salir")
        opcion = input("Seleccione una opción: ")
        if opcion == "1":
            archivo = input("Nombre del archivo a subir: ")
            with open(os.path.join(drive_folder, archivo), "w") as f:
                pass
            print(f"Archivo '{archivo}' subido con éxito.")
        elif opcion == "2":
            carpeta = input("Nombre de la carpeta a crear: ")
            carpeta_path = os.path.join(drive_folder, carpeta)
            if not os.path.exists(carpeta_path):
                os.mkdir(carpeta_path)
                print(f"Carpeta '{carpeta}' creada con éxito.")
            else:
                print(f"La carpeta '{carpeta}' ya existe.")
        elif opcion =="3":
            subir_archivo()
        elif opcion == "4":
            subir_carpeta()
        elif opcion == "5":
            descargar_y_descifrar_archivo()
        elif opcion == "6":
            sys.exit("Saliendo del programa")
        else:
            print("Opción no válida. Intente nuevamente.")

def menu_principal():
    while True:
        print("\nMenú Principal:")
        print("1. Iniciar sesión")
        print("2. Registrarse")
        print("3. Salir")
        opcion = input("Seleccione una opción: ")
        
        if opcion == "1":
            if autenticar_usuario():
                gestionar_drive()
            else:
                print("Autenticación fallida.")
        if opcion == "2":
            registrar_usuario()
        elif opcion == "3":
            print("Saliendo del programa.")
            break
        else:
            print("Opción no válida. Intente nuevamente.")

menu_principal()