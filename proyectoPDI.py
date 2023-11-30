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

# Define las variables globales
user_id=None
DATABASE_FILE = 'usuarios2.db'
SESSION_DATA_FILE = 'session_data.json'

def autenticar_usuario():
    resultado = iniciar_sesion()
    if resultado == 1:
        return True
    return False

"""
    Función: seleccionar_directorio_destino
    Esta función permite al usuario seleccionar un directorio de destino para la operación de archivo.
    Devuelve la ruta relativa del directorio seleccionado. Si no se selecciona ningún directorio, se devuelve la raíz.
"""
def seleccionar_directorio_destino():
    # Obtiene la lista de directorios disponibles para el usuario
    carpetas_disponibles = listar_directorios_usuario()
    
    # Imprime los directorios disponibles
    print("Directorios disponibles:")
    for idx, carpeta in enumerate(carpetas_disponibles):
        print(f"{idx + 1}. {carpeta}")
    
    # Solicita al usuario que seleccione un directorio
    eleccion_directorio = input("Seleccione el número del directorio destino (deje en blanco para raíz): ")
    ruta_directorio_destino = ""
    # Verifica si la entrada del usuario es un número
    if eleccion_directorio.strip().isdigit():
        idx_directorio = int(eleccion_directorio.strip()) - 1
        # Verifica si el número ingresado está dentro del rango de directorios disponibles
        if 0 <= idx_directorio < len(carpetas_disponibles):
            ruta_directorio_destino = carpetas_disponibles[idx_directorio] + "/"
    else:
        # Si la entrada del usuario no es un número, se selecciona la raíz
        ruta_directorio_destino = "./"
    return ruta_directorio_destino

"""
    Función: listar_archivos_usuario
    Esta función devuelve una lista de los archivos del usuario.
    Los archivos se identifican por su nombre si terminan en '.aes', y por su ruta relativa si comienzan con '/' o './'.
"""
def listar_archivos_usuario(user_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    # Ejecuta la consulta SQL para obtener los archivos del usuario
    cursor.execute('''
        SELECT
            CASE
                WHEN nombre_archivo LIKE "%.aes" THEN nombre_archivo
                WHEN nombre_archivo LIKE "/%" OR nombre_archivo LIKE "./%" THEN ruta_relativa
            END as nombre_o_ruta,
            nombre_archivo,
            ruta_relativa
        FROM archivos
        WHERE user_id=?
    ''', (user_id,))
    # Obtiene los resultados de la consulta y los guarda en una lista de diccionarios
    archivos = [{'nombre_o_ruta': row[0], 'nombre_archivo': row[1], 'ruta_relativa': row[2]} for row in cursor.fetchall()]
    conn.close()
    return archivos

def obtener_detalles_archivos_usuario(user_id):
    # Conectarse a la base de datos
    # 'nombre_base_datos.db' debe ser reemplazado por el nombre de tu base de datos
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    # Ejecutar la consulta SQL
    # Esta consulta selecciona las columnas archivo_id, nombre_archivo, ruta_relativa y user_id
    # de la tabla 'archivos' donde el user_id coincide con el proporcionado
    cursor.execute("""
        SELECT archivo_id, user_id, nombre_archivo, ruta_relativa
        FROM archivos
        WHERE user_id = ?
    """, (user_id,))

    # Obtener todos los resultados de la consulta
    # fetchall() devuelve una lista de tuplas donde cada tupla representa una fila de los resultados
    resultados = cursor.fetchall()

    # Convertir los resultados en una lista de diccionarios
    # Cada diccionario representa un archivo y tiene las claves 'archivo_id', 'nombre_archivo', 'ruta_relativa' y 'user_id'
    # Los índices usados para acceder a los elementos de la tupla corresponden a las columnas seleccionadas en la consulta SQL
    detalles_archivos = [
        {
            'archivo_id': resultado[0],  # Columna archivo_id
            'nombre_archivo': resultado[2],  # Columna nombre_archivo
            'ruta_relativa': resultado[3],  # Columna ruta_relativa
            'user_id': resultado[1]  # Columna user_id
        }
        for resultado in resultados
    ]

    # Cerrar la conexión a la base de datos
    # Es importante cerrar la conexión cuando hayas terminado de usarla
    conn.close()

    # Devolver la lista de diccionarios
    return detalles_archivos

"""
    Función: listar_directorios_usuario
    Esta función devuelve una lista de los directorios del usuario.
    Los directorios se identifican por su ruta relativa.
"""
def listar_directorios_usuario():
    # Obtiene el ID del usuario actual
    user_id = obtener_user_id()
    
    # Conecta con la base de datos
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    # Ejecuta la consulta SQL para obtener los directorios del usuario
    # Selecciona solo las entradas que corresponden a directorios
    cursor.execute("SELECT DISTINCT ruta_relativa FROM archivos WHERE user_id=? AND ruta_relativa != '' AND nombre_archivo NOT LIKE '%.aes'", (user_id,))
    
    # Obtiene los resultados de la consulta y los guarda en una lista
    carpetas = [row[0] for row in cursor.fetchall()]
    
    # Cierra la conexión con la base de datos
    conn.close()
    
    return carpetas

"""
    Función: obtener_datos_archivo
    Esta función devuelve los datos y la clave AES cifrada de un archivo específico perteneciente al usuario.
    Si no se encuentran datos para el archivo, se lanza una excepción FileNotFoundError.
"""
def obtener_datos_archivo(user_id, nombre_archivo):
    # Conecta con la base de datos
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    # Ejecuta la consulta SQL para obtener los datos y la clave AES cifrada del archivo
    cursor.execute('SELECT datos, clave_AES_cifrada FROM archivos WHERE user_id=? AND nombre_archivo=?', (user_id, nombre_archivo))
    
    # Obtiene el resultado de la consulta
    resultado = cursor.fetchone()
    
    # Cierra la conexión con la base de datos
    conn.close()
    
    # Si se encontraron datos para el archivo, los devuelve
    if resultado:
        datos, clave_aes_cifrada = resultado
        return datos, clave_aes_cifrada
    else:
        # Si no se encontraron datos para el archivo, lanza una excepción
        raise FileNotFoundError(f"No se encontraron datos para el archivo {nombre_archivo}")


"""
    Función: obtener_clave_aes_cifrada_de_db
    Esta función recupera la clave AES cifrada de un archivo específico de la base de datos.
    Argumentos:
        user_id: El ID del usuario que posee el archivo.
        nombre_archivo: El nombre del archivo del que se va a recuperar la clave.
    Devuelve:
        La clave AES cifrada del archivo.
"""
def obtener_clave_aes_cifrada_de_db(user_id, nombre_archivo):
    # Conecta con la base de datos
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    # Ejecuta la consulta SQL para obtener la clave AES cifrada del archivo
    cursor.execute('SELECT clave_AES_cifrada FROM archivos WHERE user_id=? AND nombre_archivo=?',
                   (user_id, nombre_archivo))
    
    # Obtiene el resultado de la consulta
    clave_aes_cifrada = cursor.fetchone()[0]
    
    # Cierra la conexión con la base de datos
    conn.close()
    
    return clave_aes_cifrada

"""
    Función: descifrar_clave_aes_con_rsa
    Esta función descifra una clave AES cifrada utilizando una clave privada RSA.
    Argumentos:
        clave_aes_cifrada: La clave AES cifrada que se va a descifrar.
    Devuelve:
        La clave AES descifrada.
"""
def descifrar_clave_aes_con_rsa(clave_aes_cifrada):
    try:
        # Importa la clave privada RSA de la variable global
        private_key = RSA.import_key(bdd.clave_privada_rsa_global)

        # Crea un objeto de cifrado RSA con la clave privada
        cipher_rsa = PKCS1_OAEP.new(private_key)
        
        # Descifra la clave AES con el objeto de cifrado RSA
        clave_aes = cipher_rsa.decrypt(clave_aes_cifrada)
        
        return clave_aes

    except Exception as e:
        # Imprime cualquier error que ocurra durante el proceso de descifrado
        print(f"Error al usar la clave privada RSA: {e}")
        raise

"""
    Función: guardar_archivo_en_db
    Esta función guarda un archivo cifrado en la base de datos.
    Argumentos:
        user_id: El ID del usuario que posee el archivo.
        nombre_archivo: El nombre del archivo que se va a guardar.
        nonce: El nonce utilizado en el cifrado AES.
        tag: El tag generado por el cifrado AES.
        datos_cifrados: Los datos cifrados del archivo.
        clave_aes_cifrada: La clave AES cifrada utilizada para cifrar el archivo.
        ruta_relativa: La ruta relativa del archivo en el sistema de archivos del usuario.
"""
def guardar_archivo_en_db(user_id, nombre_archivo, nonce, tag, datos_cifrados, clave_aes_cifrada, ruta_relativa="./"):
    # Conecta con la base de datos
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    # Combina el nonce, el tag y los datos cifrados en una sola variable
    datos_completos = nonce + tag + datos_cifrados
    
    # Ejecuta la consulta SQL para insertar el archivo en la base de datos
    cursor.execute('''
        INSERT INTO archivos (user_id, nombre_archivo, datos, clave_AES_cifrada, ruta_relativa)
        VALUES (?, ?, ?, ?, ?)''',
        (user_id, nombre_archivo, datos_completos, clave_aes_cifrada, ruta_relativa))
    
    # Confirma los cambios en la base de datos
    conn.commit()
    
    # Cierra la conexión con la base de datos
    conn.close()

"""
    Función: crear_archivo_o_carpeta_en_db
    Esta función crea una entrada en la base de datos para un archivo o carpeta.
    Argumentos:
        user_id: El ID del usuario que posee el archivo o carpeta.
        nombre_archivo: El nombre del archivo o carpeta.
        ruta_relativa: La ruta relativa del archivo o carpeta en el sistema de archivos del usuario.
        es_carpeta: Un booleano que indica si la entrada es una carpeta.
        nonce: El nonce utilizado en el cifrado AES (solo para archivos).
        tag: El tag generado por el cifrado AES (solo para archivos).
        datos_cifrados: Los datos cifrados del archivo (solo para archivos).
        clave_aes_cifrada: La clave AES cifrada utilizada para cifrar el archivo (solo para archivos).
"""
def crear_archivo_o_carpeta_en_db(user_id, nombre_archivo, ruta_relativa, es_carpeta, nonce=None, tag=None, datos_cifrados=None, clave_aes_cifrada=None):
    # Conecta con la base de datos
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    if es_carpeta:
        # Si la entrada es una carpeta, inserta solo el ID del usuario, el nombre y la ruta
        cursor.execute('INSERT INTO archivos (user_id, nombre_archivo, ruta_relativa) VALUES (?, ?, ?)', 
                       (user_id, nombre_archivo, ruta_relativa))
    else:
        # Si la entrada es un archivo, combina el nonce, el tag y los datos cifrados
        datos_completos = nonce + tag + datos_cifrados if datos_cifrados is not None else b''
        # Inserta el ID del usuario, el nombre, los datos, la clave AES cifrada y la ruta
        cursor.execute('INSERT INTO archivos (user_id, nombre_archivo, datos, clave_AES_cifrada, ruta_relativa) VALUES (?, ?, ?, ?, ?)',
                       (user_id, nombre_archivo, datos_completos, clave_aes_cifrada, ruta_relativa))

    # Confirma los cambios en la base de datos
    conn.commit()
    # Cierra la conexión con la base de datos
    conn.close()
    
"""
    Función: cifrar_y_guardar_archivo_en_db
    Esta función cifra un archivo local y lo guarda en la base de datos.
    Argumentos:
        user_id: El ID del usuario que posee el archivo.
        archivo: La ruta del archivo que se va a cifrar y guardar.
        ruta_directorio_destino: La ruta del directorio donde se guardará el archivo en la base de datos.
"""
def cifrar_y_guardar_archivo_en_db(user_id, archivo, ruta_directorio_destino):
    # Abre el archivo en modo binario y lee sus datos
    with open(archivo, 'rb') as f:
        datos_archivo = f.read()

    # Cifra los datos del archivo con AES
    nonce, tag, datos_cifrados, clave_aes_cifrada = cifrar_con_aes(user_id, datos_archivo)
    
    # Añade la extensión '.aes' al nombre del archivo
    nombre_archivo_cifrado = os.path.basename(archivo) + '.aes'
    
    # Guarda el archivo cifrado en la base de datos
    guardar_archivo_en_db(user_id, nombre_archivo_cifrado, nonce, tag, datos_cifrados, clave_aes_cifrada, ruta_directorio_destino)

"""
    Esta función cifra una carpeta y sus archivos y los guarda en la base de datos.
    
    Argumentos:
    user_id: El ID del usuario que posee la carpeta.
    carpeta_seleccionada: La ruta de la carpeta que se va a cifrar y guardar.
    ruta_directorio_destino: La ruta del directorio donde se guardará la carpeta en la base de datos.
"""
def cifrar_y_guardar_carpeta_en_db(user_id, carpeta_seleccionada, ruta_directorio_destino):
    # Obtiene el nombre de la carpeta
    nombre_carpeta = os.path.basename(carpeta_seleccionada)

    # Recorre la carpeta y sus subcarpetas
    for raiz, _, archivos in os.walk(carpeta_seleccionada):
        for nombre_archivo in archivos:
            # Obtiene la ruta completa del archivo
            ruta_archivo = os.path.join(raiz, nombre_archivo)
            
            # Obtiene la ruta relativa del archivo respecto a la carpeta seleccionada
            ruta_relativa = os.path.relpath(ruta_archivo, carpeta_seleccionada)
            
            # Cifra y guarda el archivo en la base de datos
            cifrar_y_guardar_archivo_en_db(user_id, ruta_archivo, ruta_directorio_destino + nombre_carpeta + '/')

    # Crea una entrada en la base de datos para la carpeta
    crear_archivo_o_carpeta_en_db(user_id, "/" + nombre_carpeta, ruta_directorio_destino + nombre_carpeta + '/', True)
    
"""
    Esta función descarga y descifra un archivo individual de la base de datos.
    
    Argumentos:
    user_id: El ID del usuario que posee el archivo.
    nombre_archivo: El nombre del archivo que se va a descargar y descifrar.
    ruta_descarga: La ruta donde se guardará el archivo descargado y descifrado.
"""
def descargar_y_descifrar_archivo_individual(user_id, nombre_archivo, ruta_descarga):
    # Obtiene los datos cifrados y la clave AES cifrada del archivo de la base de datos
    datos, clave_aes_cifrada = obtener_datos_archivo(user_id, nombre_archivo)

    # Descifra la clave AES con RSA
    clave_aes = descifrar_clave_aes_con_rsa(clave_aes_cifrada)

    # Intenta descifrar los datos del archivo con AES
    try:
        datos_descifrados = descifrar_con_aes(datos, clave_aes)
        
        # Elimina la extensión '.aes' del nombre del archivo
        nombre_archivo_descifrado = nombre_archivo.replace('.aes', '')
        
        # Crea la ruta completa del archivo descifrado
        ruta_archivo_descifrado = os.path.join(ruta_descarga, nombre_archivo_descifrado)
        
        # Reemplaza los caracteres en la ruta de descarga
        ruta_archivo_descifrado = ruta_archivo_descifrado.replace('\\', '/').replace('//', '/').replace('./', '').replace('\\./', '/').replace('\\\\./', '/')

        # Escribe los datos descifrados en el archivo
        with open(ruta_archivo_descifrado, 'wb') as f:
            f.write(datos_descifrados)
        
        print(f"Archivo {nombre_archivo_descifrado} descargado y descifrado.")
    except Exception as e:
        print(f"Error al descifrar {nombre_archivo}: {e}")
        
"""
    Esta función descarga y descifra una carpeta completa de la base de datos.
    
    Argumentos:
    user_id: El ID del usuario que posee la carpeta.
    ruta_carpeta: La ruta de la carpeta que se va a descargar y descifrar.
    ruta_descarga: La ruta donde se guardará la carpeta descargada y descifrada.
"""
def descargar_y_descifrar_carpeta(user_id, ruta_carpeta, ruta_descarga):
    # Obtener todos los archivos del usuario
    todos_los_archivos = obtener_detalles_archivos_usuario(user_id)

    # Filtrar para obtener solo los archivos dentro de la carpeta seleccionada y que terminan en '.aes'
    archivos_en_carpeta = [archivo for archivo in todos_los_archivos 
                           if archivo['ruta_relativa'].startswith(ruta_carpeta) and archivo['nombre_archivo'].endswith('.aes')]
    
    # Crea la carpeta en el directorio de descargas si no existe
    os.makedirs(os.path.join(ruta_descarga, ruta_carpeta), exist_ok=True)

    for archivo in archivos_en_carpeta:
        # Crea la ruta de descarga del archivo
        ruta_descarga_archivo = os.path.join(ruta_descarga, ruta_carpeta)
        # Reemplaza los caracteres en la ruta de descarga
        ruta_descarga_archivo = ruta_descarga_archivo.replace('\\', '/').replace('//', '/').replace('./', '').replace('\\./', '/').replace('\\\\./', '/')
        # Descarga y descifra el archivo
        descargar_y_descifrar_archivo_individual(user_id, archivo['nombre_archivo'], ruta_descarga_archivo)

"""
    Esta función permite al usuario seleccionar y descargar archivos o carpetas de la base de datos.
    Los archivos se descifran antes de ser guardados en el sistema de archivos local.
"""
def descargar_y_descifrar_archivo():
    # Obtiene el ID del usuario
    user_id = obtener_user_id()
    
    # Crea la ruta de descarga
    ruta_descarga = os.path.join(str(bdd.nombre_usuario_global), "Descargas")
    
    # Reemplaza los caracteres en la ruta de descarga
    ruta_descarga = ruta_descarga.replace('\\', '/').replace('//', '/').replace('.', '')
    
    # Crea el directorio de descarga si no existe
    os.makedirs(ruta_descarga, exist_ok=True)

    # Obtiene la lista de archivos del usuario
    elementos = listar_archivos_usuario(user_id)
    
    # Si no hay archivos, imprime un mensaje y termina la función
    if not elementos:
        print("No hay archivos disponibles.")
        return

    # Imprime la lista de archivos disponibles
    for idx, elemento in enumerate(elementos):
        if elemento['nombre_archivo'].endswith('.aes'):
            print(f"{idx + 1}. {(elemento['ruta_relativa'] + '/' + elemento['nombre_archivo']).replace('//', '/')}")
        else:
            print(f"{idx + 1}. {elemento['nombre_archivo']}")

    # Solicita al usuario que seleccione los archivos a descargar
    eleccion = input("Ingrese los números de los elementos a descargar, separados por comas: ")
    
    # Convierte la elección del usuario en una lista de índices
    indices_seleccionados = [int(x.strip()) - 1 for x in eleccion.split(',') if x.strip().isdigit()]

    # Para cada índice seleccionado, descarga y descifra el archivo correspondiente
    for idx in indices_seleccionados:
        if 0 <= idx < len(elementos):
            nombre_elemento = elementos[idx]['nombre_archivo']
            if nombre_elemento.endswith('.aes'):
                # Si el elemento es un archivo, lo descarga y descifra
                descargar_y_descifrar_archivo_individual(user_id, nombre_elemento, ruta_descarga)
            else:
                # Si el elemento es una carpeta, descarga y descifra la carpeta completa
                descargar_y_descifrar_carpeta(user_id, nombre_elemento, ruta_descarga)
        else:
            print(f"Índice {idx + 1} no válido.")

"""
    Esta función permite al usuario seleccionar uno o más archivos para subir a la base de datos.
    Los archivos se cifran antes de ser guardados en la base de datos.
"""
def subir_archivo():
    # Obtiene el ID del usuario
    user_id = obtener_user_id()

    # Solicita al usuario que seleccione el directorio de destino
    ruta_directorio_destino = seleccionar_directorio_destino()

    # Abre un cuadro de diálogo para seleccionar archivos
    root = tk.Tk()
    root.withdraw()
    archivos = filedialog.askopenfilenames()
    root.destroy()

    # Si no se seleccionó ningún archivo, termina la función
    if not archivos:
        print("No se seleccionó ningún archivo.")
        return

    # Para cada archivo seleccionado, lo cifra y lo guarda en la base de datos
    for archivo in archivos:
        cifrar_y_guardar_archivo_en_db(user_id, archivo, ruta_directorio_destino)

    print(f"{len(archivos)} archivo(s) subido(s) con éxito.")
    
"""
    Esta función permite al usuario seleccionar una carpeta para subir a la base de datos.
    Los archivos dentro de la carpeta se cifran antes de ser guardados en la base de datos.
"""
def subir_carpeta():
    # Obtiene el ID del usuario
    user_id = obtener_user_id()

    # Solicita al usuario que seleccione el directorio de destino
    ruta_directorio_destino = seleccionar_directorio_destino()
    if ruta_directorio_destino.endswith('//'):
                    ruta_directorio_destino = ruta_directorio_destino[:-1]

    # Abre un cuadro de diálogo para seleccionar una carpeta
    root = tk.Tk()
    root.withdraw()
    carpeta_seleccionada = filedialog.askdirectory()
    root.destroy()

    # Si no se seleccionó ninguna carpeta, termina la función
    if not carpeta_seleccionada:
        print("No se seleccionó una carpeta.")
        return
    
    # Cifra y guarda la carpeta en la base de datos
    cifrar_y_guardar_carpeta_en_db(user_id, carpeta_seleccionada, ruta_directorio_destino)

    print(f"Carpeta '{os.path.basename(carpeta_seleccionada)}' subida y cifrada con éxito.")

"""
    Esta función permite al usuario crear un nuevo archivo o carpeta en la base de datos.
    Si se crea un archivo, se cifra antes de ser guardado en la base de datos.
"""
def crear_archivo_o_carpeta():
    # Obtiene el ID del usuario
    user_id = obtener_user_id()

    # Solicita al usuario que seleccione el directorio de destino
    ruta_directorio_destino = seleccionar_directorio_destino()

    # Solicita al usuario que ingrese el nombre del archivo o carpeta
    nombre = input("Ingrese el nombre del archivo/carpeta: ")

    # Pregunta al usuario si está creando una carpeta
    es_carpeta = input("Es una carpeta? (s/n): ").lower() == 's'

    if es_carpeta:
        # Si el usuario está creando una carpeta, la crea en la base de datos
        crear_archivo_o_carpeta_en_db(user_id, ruta_directorio_destino + nombre, ruta_directorio_destino + nombre, True)
    else:
        # Si el usuario está creando un archivo, lo cifra y lo guarda en la base de datos
        nonce, tag, datos_cifrados, clave_aes_cifrada = cifrar_con_aes(user_id, b'')
        crear_archivo_o_carpeta_en_db(user_id, nombre + '.aes', ruta_directorio_destino, False, nonce, tag, datos_cifrados, clave_aes_cifrada)

    print(f"{'Carpeta' if es_carpeta else 'Archivo'} '{nombre}' creado con éxito.")

"""
    Esta función lee el archivo de datos de la sesión y devuelve el ID del usuario.
"""
def obtener_user_id():
    # Abre el archivo de datos de la sesión en modo lectura
    with open(SESSION_DATA_FILE, 'r') as file:
        # Carga los datos de la sesión en formato JSON
        session_data = json.load(file)
    # Devuelve el ID del usuario
    return session_data.get('user_uuid')

"""
    Esta función proporciona un menú de opciones para que el usuario pueda interactuar con el sistema de archivos.
    El usuario puede crear archivos o carpetas, subir archivos o carpetas, descargar archivos o salir del programa.
"""
def gestionar_drive():
    # Bucle infinito para mantener el menú de opciones en ejecución hasta que el usuario decida salir
    while True:
        # Imprime el menú de opciones
        print("\nMenú de opciones:")
        print("1. Crear archivo o carpeta")
        print("2. Subir archivo")
        print("3. Subir carpeta")
        print("4. Descargar archivos")
        print("5. Salir")
        # Solicita al usuario que seleccione una opción
        opcion = input("Seleccione una opción: ")
        # Ejecuta la opción seleccionada por el usuario
        if opcion == "1":
            crear_archivo_o_carpeta()
        elif opcion =="2":
            subir_archivo()
        elif opcion == "3":
            subir_carpeta()
        elif opcion == "4":
            descargar_y_descifrar_archivo()
        elif opcion == "5":
            # Si el usuario selecciona la opción de salir, termina el programa
            sys.exit("Saliendo del programa")
        else:
            # Si el usuario selecciona una opción no válida, imprime un mensaje de error
            print("Opción no válida. Intente nuevamente.")

"""
    Esta función proporciona un menú principal para que el usuario pueda interactuar con el sistema.
    El usuario puede iniciar sesión, registrarse o salir del programa.
"""
def menu_principal():
    # Bucle infinito para mantener el menú principal en ejecución hasta que el usuario decida salir
    while True:
        # Imprime el menú principal
        print("\nMenú Principal:")
        print("1. Iniciar sesión")
        print("2. Registrarse")
        print("3. Salir")
        # Solicita al usuario que seleccione una opción
        opcion = input("Seleccione una opción: ")
        
        # Ejecuta la opción seleccionada por el usuario
        if opcion == "1":
            # Si el usuario selecciona la opción de iniciar sesión, intenta iniciar sesión
            if iniciar_sesion():
                # Si la autenticación es exitosa, permite al usuario gestionar su drive
                gestionar_drive()
            else:
                # Si la autenticación falla, imprime un mensaje de error y vuelve al menú principal
                print("Autenticación fallida.")
                continue
        if opcion == "2":
            # Si el usuario selecciona la opción de registrarse, registra al usuario
            registrar_usuario()
        elif opcion == "3":
            # Si el usuario selecciona la opción de salir, termina el programa
            print("Saliendo del programa.")
            break
        else:
            # Si el usuario selecciona una opción no válida, imprime un mensaje de error
            print("Opción no válida. Intente nuevamente.")

# Ejecuta el menú principal
menu_principal()