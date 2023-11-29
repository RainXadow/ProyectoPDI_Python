import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tkinter as tk
from tkinter import filedialog

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

import bdd
from bdd import (cifrar_con_aes, descifrar_con_aes, iniciar_sesion,
                 registrar_usuario, seleccion)

user_id=None
DATABASE_FILE = 'usuarios2.db'
SESSION_DATA_FILE = 'session_data.json'

def autenticar_usuario():
    resultado = iniciar_sesion()
    if resultado == 1:
        return True
    return False

"""
    Permite al usuario seleccionar un directorio de destino y devuelve la ruta relativa seleccionada.
    Si no se selecciona ningún directorio, se devuelve la raíz.
"""
def seleccionar_directorio_destino():
    
    carpetas_disponibles = listar_directorios_usuario()
    
    print("Directorios disponibles:")
    for idx, carpeta in enumerate(carpetas_disponibles):
        print(f"{idx + 1}. {carpeta}")
    
    eleccion_directorio = input("Seleccione el número del directorio destino (deje en blanco para raíz): ")
    ruta_directorio_destino = ""
    if eleccion_directorio.strip().isdigit():
        idx_directorio = int(eleccion_directorio.strip()) - 1
        if 0 <= idx_directorio < len(carpetas_disponibles):
            ruta_directorio_destino = carpetas_disponibles[idx_directorio] + "/"
    else:
        ruta_directorio_destino = "./"
    return ruta_directorio_destino

def listar_archivos_usuario(user_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT nombre_archivo FROM archivos WHERE user_id=?', (user_id,))
    archivos = [row[0] for row in cursor.fetchall()]
    conn.close()
    return archivos

def listar_directorios_usuario():
    user_id = obtener_user_id()
    
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    # Seleccionar solo las entradas que corresponden a directorios
    cursor.execute("SELECT DISTINCT ruta_relativa FROM archivos WHERE user_id=? AND ruta_relativa != '' AND nombre_archivo NOT LIKE '%.aes'", (user_id,))
    carpetas = [row[0] for row in cursor.fetchall()]
    conn.close()
    return carpetas

def obtener_datos_archivo(user_id, nombre_archivo):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT datos, clave_AES_cifrada FROM archivos WHERE user_id=? AND nombre_archivo=?', (user_id, nombre_archivo))
    resultado = cursor.fetchone()
    conn.close()
    if resultado:
        datos, clave_aes_cifrada = resultado
        return datos, clave_aes_cifrada
    else:
        raise FileNotFoundError(f"No se encontraron datos para el archivo {nombre_archivo}")

def obtener_clave_aes_cifrada_de_db(user_id, nombre_archivo):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT clave_AES_cifrada FROM archivos WHERE user_id=? AND nombre_archivo=?',
                   (user_id, nombre_archivo))
    clave_aes_cifrada = cursor.fetchone()[0]
    conn.close()
    return clave_aes_cifrada

def descifrar_clave_aes_con_rsa(clave_aes_cifrada):
    try:
        # Usar la clave privada de la variable global
        private_key = RSA.import_key(bdd.clave_privada_rsa_global)

        # Descifrar la clave AES con la clave privada RSA
        cipher_rsa = PKCS1_OAEP.new(private_key)
        clave_aes = cipher_rsa.decrypt(clave_aes_cifrada)
        return clave_aes

    except Exception as e:
        print(f"Error al usar la clave privada RSA: {e}")
        raise

def guardar_archivo_en_db(user_id, nombre_archivo, nonce, tag, datos_cifrados, clave_aes_cifrada, ruta_relativa="./"):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    datos_completos = nonce + tag + datos_cifrados
    cursor.execute('''
        INSERT INTO archivos (user_id, nombre_archivo, datos, clave_AES_cifrada, ruta_relativa) 
        VALUES (?, ?, ?, ?, ?)''',
        (user_id, nombre_archivo, datos_completos, clave_aes_cifrada, ruta_relativa))
    conn.commit()
    conn.close()

def crear_archivo_o_carpeta_en_db(user_id, nombre_archivo, ruta_relativa, es_carpeta, nonce=None, tag=None, datos_cifrados=None, clave_aes_cifrada=None):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    if es_carpeta:
        cursor.execute('INSERT INTO archivos (user_id, nombre_archivo, ruta_relativa) VALUES (?, ?, ?)', (user_id, nombre_archivo, ruta_relativa))
    else:
        datos_completos = nonce + tag + datos_cifrados if datos_cifrados is not None else b''
        cursor.execute('INSERT INTO archivos (user_id, nombre_archivo, datos, clave_AES_cifrada, ruta_relativa) VALUES (?, ?, ?, ?, ?)', 
                       (user_id, nombre_archivo, datos_completos, clave_aes_cifrada, ruta_relativa))

    conn.commit()
    conn.close()
    
"""
    Cifra EN LOCAL y guarda un archivo en la base de datos.
"""
def cifrar_y_guardar_archivo_en_db(user_id, archivo, ruta_directorio_destino):
    with open(archivo, 'rb') as f:
        datos_archivo = f.read()

    nonce, tag, datos_cifrados, clave_aes_cifrada = cifrar_con_aes(user_id, datos_archivo)
    nombre_archivo_cifrado = os.path.basename(archivo) + '.aes'
    guardar_archivo_en_db(user_id, nombre_archivo_cifrado, nonce, tag, datos_cifrados, clave_aes_cifrada, ruta_directorio_destino)

def cifrar_y_guardar_carpeta_en_db(user_id, carpeta_seleccionada, ruta_directorio_destino):
    """
    Cifra y guarda una carpeta y sus archivos en la base de datos.
    """
    nombre_carpeta = os.path.basename(carpeta_seleccionada)

    for raiz, _, archivos in os.walk(carpeta_seleccionada):
        for nombre_archivo in archivos:
            ruta_archivo = os.path.join(raiz, nombre_archivo)
            ruta_relativa = os.path.relpath(ruta_archivo, carpeta_seleccionada)
            cifrar_y_guardar_archivo_en_db(user_id, ruta_archivo, ruta_directorio_destino + nombre_carpeta + '/' + ruta_relativa)

    crear_archivo_o_carpeta_en_db(user_id, "/" + nombre_carpeta, ruta_directorio_destino + nombre_carpeta + '/', True)
    
def descargar_y_descifrar_archivo_individual(user_id, nombre_archivo, ruta_descarga):
    datos, clave_aes_cifrada = obtener_datos_archivo(user_id, nombre_archivo)

    # Descifrar la clave AES
    clave_aes = descifrar_clave_aes_con_rsa(clave_aes_cifrada)

    # Descifrar los datos del archivo
    try:
        datos_descifrados = descifrar_con_aes(datos, clave_aes)
        nombre_archivo_descifrado = nombre_archivo.replace('.aes', '')
        ruta_archivo_descifrado = os.path.join(ruta_descarga, nombre_archivo_descifrado)

        with open(ruta_archivo_descifrado, 'wb') as f:
            f.write(datos_descifrados)
        print(f"Archivo {nombre_archivo_descifrado} descargado y descifrado.")
    except Exception as e:
        print(f"Error al descifrar {nombre_archivo}: {e}")
        
def descargar_y_descifrar_carpeta(user_id, ruta_carpeta, ruta_descarga):
    # Obtener todos los archivos dentro de la carpeta
    archivos_en_carpeta = [archivo for archivo in listar_archivos_usuario(user_id) if archivo.startswith(ruta_carpeta)]
    for archivo in archivos_en_carpeta:
        descargar_y_descifrar_archivo_individual(user_id, archivo, os.path.join(ruta_descarga, ruta_carpeta))



# Descargamos y desciframos
def descargar_y_descifrar_archivo():
    user_id = obtener_user_id()
    ruta_descarga = os.path.join(str(bdd.nombre_usuario_global), "Descargas")
    os.makedirs(ruta_descarga, exist_ok=True)

    elementos = listar_archivos_usuario(user_id)
    if not elementos:
        print("No hay archivos disponibles.")
        return

    # Mostrar los elementos disponibles
    for idx, elemento in enumerate(elementos):
        print(f"{idx + 1}. {elemento}")

    eleccion = input("Ingrese los números de los elementos a descargar, separados por comas: ")
    indices_seleccionados = [int(x.strip()) - 1 for x in eleccion.split(',') if x.strip().isdigit()]

    for idx in indices_seleccionados:
        if 0 <= idx < len(elementos):
            nombre_elemento = elementos[idx]
            if nombre_elemento.endswith('.aes'):
                # Es un archivo
                descargar_y_descifrar_archivo_individual(user_id, nombre_elemento, ruta_descarga)
            else:
                # Es una carpeta
                descargar_y_descifrar_carpeta(user_id, nombre_elemento, ruta_descarga)
        else:
            print(f"Índice {idx + 1} no válido.")


# Ciframos el archivo y lo subimos
def subir_archivo():
    user_id = obtener_user_id()

    ruta_directorio_destino = seleccionar_directorio_destino()

    root = tk.Tk()
    root.withdraw()
    archivos = filedialog.askopenfilenames()
    root.destroy()

    if not archivos:
        print("No se seleccionó ningún archivo.")
        return

    for archivo in archivos:
        cifrar_y_guardar_archivo_en_db(user_id, archivo, ruta_directorio_destino)

    print(f"{len(archivos)} archivo(s) subido(s) con éxito.")
    
def subir_carpeta():
    user_id = obtener_user_id()

    ruta_directorio_destino = seleccionar_directorio_destino()

    root = tk.Tk()
    root.withdraw()
    carpeta_seleccionada = filedialog.askdirectory()
    root.destroy()

    if not carpeta_seleccionada:
        print("No se seleccionó una carpeta.")
        return
    
    # Obtener el nombre de la carpeta y formatearlo como directorio
    nombre_carpeta = os.path.basename(carpeta_seleccionada)

    cifrar_y_guardar_carpeta_en_db(user_id, carpeta_seleccionada, ruta_directorio_destino)

    print(f"Carpeta '{os.path.basename(carpeta_seleccionada)}' subida y cifrada con éxito.")



def crear_archivo_o_carpeta():
    user_id = obtener_user_id()

    ruta_directorio_destino = seleccionar_directorio_destino()

    nombre = input("Ingrese el nombre del archivo/carpeta: ")
    es_carpeta = input("Es una carpeta? (s/n): ").lower() == 's'

    if es_carpeta:
        crear_archivo_o_carpeta_en_db(user_id, ruta_directorio_destino + nombre, ruta_directorio_destino + nombre, True)
    else:
        # Cifrar el archivo vacío
        nonce, tag, datos_cifrados, clave_aes_cifrada = cifrar_con_aes(user_id, b'')
        crear_archivo_o_carpeta_en_db(user_id, nombre + '.aes', ruta_directorio_destino, False, nonce, tag, datos_cifrados, clave_aes_cifrada)

    print(f"{'Carpeta' if es_carpeta else 'Archivo'} '{nombre}' creado con éxito.")


def obtener_user_id():
    with open(SESSION_DATA_FILE, 'r') as file:
        session_data = json.load(file)
    return session_data.get('user_uuid')

def gestionar_drive():
    while True:
        print("\nMenú de opciones:")
        print("1. Crear archivo o carpeta")
        print("2. Subir archivo")
        print("3. Subir carpeta")
        print("4. Descargar archivos")
        print("5. Salir")
        opcion = input("Seleccione una opción: ")
        if opcion == "1":
            crear_archivo_o_carpeta()
        elif opcion =="2":
            subir_archivo()
        elif opcion == "3":
            subir_carpeta()
        elif opcion == "4":
            descargar_y_descifrar_archivo()
        elif opcion == "5":
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
            if iniciar_sesion():
                gestionar_drive()
            else:
                print("Autenticación fallida.")
                continue
        if opcion == "2":
            registrar_usuario()
        elif opcion == "3":
            print("Saliendo del programa.")
            break
        else:
            print("Opción no válida. Intente nuevamente.")

menu_principal()