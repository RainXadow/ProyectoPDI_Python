import json
import os
import re
import sqlite3
import sys
import tkinter as tk
from tkinter import filedialog

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

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
    Esta función firma los datos proporcionados utilizando la clave privada RSA del usuario actual.

    Parámetros:
    datos (bytes): Los datos que se van a firmar. Deben ser bytes, no una cadena de texto.

    Retorna:
    bytes: La firma de los datos, que es un objeto de bytes.
"""
def firmar_datos(datos):
    private_key = bdd.clave_privada_rsa_global
    private_key2 = load_pem_private_key(private_key, password=None)
    # Firmamos los datos
    signature = private_key2.sign(
        datos,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Devolvemos la firma
    return signature

"""
    Esta función verifica una firma utilizando la clave pública RSA del usuario que compartió los datos.

    Parámetros:
    nombre_usuario_comparte (str): El nombre de usuario del usuario que compartió los datos.
    signature (bytes): La firma que se va a verificar. Debe ser un objeto de bytes, no una cadena de texto.
    original_data (bytes): Los datos originales que se firmaron. Deben ser bytes, no una cadena de texto.

    Retorna:
    bool: True si la firma es válida, False en caso contrario.
"""
def verificar_firma(nombre_usuario_comparte, signature, original_data):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT public_key FROM usuarios WHERE username=?', (nombre_usuario_comparte,))
    result = cursor.fetchone()
    conn.close()

    if result is None:
        print("El nombre de usuario no existe.")
        return False

    clave_publica_rsa = result[0]
    
    # Cargamos la clave pública
    public_key = serialization.load_pem_public_key(clave_publica_rsa.encode())

    try:
        # Verificamos la firma
        public_key.verify(
            signature,
            original_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("La firma es válida.")
        return True
    except InvalidSignature:
        print("La firma es inválida.")
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
def listar_archivos_usuario():
    user_id = obtener_user_id()
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
            ruta_relativa,
            firma,
            nombre_usuario_comparte,
            datos
        FROM archivos
        WHERE user_id=?
    ''', (user_id,))
    # Obtiene los resultados de la consulta y los guarda en una lista de diccionarios
    archivos = [{'nombre_o_ruta': row[0], 'nombre_archivo': row[1], 'ruta_relativa': row[2], 'firma': row[3], 'nombre_usuario_comparte': row[4], 'datos': row[5]} for row in cursor.fetchall()]
    conn.close()
    return archivos


"""
    Esta función se encarga de listar los archivos que un usuario puede compartir.

    Primero, obtiene el ID del usuario actual y establece una conexión con la base de datos SQLite.
    Luego, realiza una consulta SQL para obtener los nombres de los archivos que pertenecen al usuario y que están disponibles para compartir (es decir, aquellos cuyos datos y clave_AES_cifrada no son NULL).

    Si la consulta devuelve algún resultado, se imprime una lista numerada de los nombres de los archivos.
    Luego, se solicita al usuario que ingrese los números correspondientes a los archivos que desea compartir.

    La función devuelve una lista con los nombres de los archivos seleccionados por el usuario.

    Parámetros:
    Ninguno.

    Devuelve:
    Una lista de strings con los nombres de los archivos que el usuario desea compartir. Si el usuario no selecciona ningún archivo, la función devuelve None.
    """
def listar_archivos_usuario_compartir():
    user_id = obtener_user_id()
    
    # Conecta a la base de datos
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    # Consulta los archivos del usuario por su ID de usuario que no tienen datos y clave_AES_cifrada establecidos en NULL
    cursor.execute('''
        SELECT nombre_archivo
        FROM archivos
        WHERE user_id = ? AND datos IS NOT NULL AND clave_AES_cifrada IS NOT NULL
    ''', (user_id,))

    # Obtiene el resultado de la consulta
    result = cursor.fetchall()

    # Cierra la conexión a la base de datos
    conn.close()

    # Si el resultado no es None, imprime los nombres de los archivos
    if result is not None:
        print("\n TUS ARCHIVOS:\n")
        for i, row in enumerate(result, start=1):
            print(f"{i}. {row[0]}")
    else:
        print("No tienes archivos.")

    # Solicita al usuario que seleccione los archivos que quiere compartir
    archivos_a_compartir = input("Ingrese los números de los archivos que desea compartir, separados por comas: ")
    
    # Si no se seleccionó ningún archivo, termina la función
    if not archivos_a_compartir:
        print("No seleccionaste ningún archivo para compartir.")
        return
    
    archivos_a_compartir = [int(num) for num in archivos_a_compartir.split(",")]

    # Devuelve una lista con los nombres de los archivos seleccionados
    return [result[i-1][0] for i in archivos_a_compartir if 1 <= i <= len(result)]

"""
Esta función se utiliza para obtener el ID de un usuario en la base de datos a partir de su nombre de usuario.

Parámetros:
    username (str): El nombre de usuario del usuario cuyo ID se quiere obtener.

Devuelve:
    user_id (int o None): El ID del usuario si se encuentra en la base de datos; None si no se encuentra.

Funcionamiento:
    1. Se establece una conexión con la base de datos.
    2. Se crea un cursor para ejecutar consultas SQL.
    3. Se ejecuta una consulta SQL para seleccionar el ID del usuario de la tabla 'usuarios' donde el nombre de usuario coincide con el proporcionado.
    4. Se obtiene el primer resultado de la consulta (si existe) con `fetchone()`.
    5. Se cierra la conexión a la base de datos.
    6. Si se encontró un resultado, se devuelve el ID del usuario (que es el primer y único elemento de la tupla resultante). Si no se encontró ningún resultado, se devuelve None.
"""
def obtener_id_usuario_por_nombre(username):
    # Conecta a la base de datos
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    # Consulta el ID del usuario por su nombre de usuario
    cursor.execute('''
        SELECT ID
        FROM usuarios
        WHERE username = ?
    ''', (username,))

    # Obtiene el resultado de la consulta
    result = cursor.fetchone()

    # Cierra la conexión a la base de datos
    conn.close()

    # Si el resultado no es None, devuelve el ID del usuario
    if result is not None:
        return result[0]
    else:
        return None

"""
Esta función se utiliza para compartir archivos entre dos usuarios en el sistema.

Parámetros:
    username_2 (str): El nombre de usuario del Usuario 2 con el que el Usuario 1 quiere compartir archivos.

Devuelve:
    None

Funcionamiento:
    1. Obtiene el ID del Usuario 2 por su nombre de usuario.
    2. Si no se encuentra el Usuario 2, termina la función e imprime un mensaje de error.
    3. Lista los archivos del Usuario 1 y obtiene los nombres de los archivos que el usuario quiere compartir.
    4. Si no se seleccionó ningún archivo, termina la función e imprime un mensaje de error.
    5. Obtiene el ID del Usuario 1.
    6. Si no se encuentra el Usuario 1, termina la función e imprime un mensaje de error.
    7. Para cada archivo que el Usuario 1 quiere compartir, hace lo siguiente:
        a. Obtiene la clave AES cifrada del archivo del Usuario 1.
        b. Descifra la clave AES con la clave privada del Usuario 1.
        c. Intenta descifrar los datos del archivo con AES.
        d. Si el descifrado es exitoso, elimina la extensión '.aes' del nombre del archivo y cifra los datos descifrados con la clave pública del Usuario 2. Luego, guarda los datos cifrados en la base de datos asociados al Usuario 2.
        e. Si ocurre un error durante el descifrado, imprime un mensaje de error y continúa con el siguiente archivo.
"""
def compartir_archivo_con_usuario(username_2):
    # Obtén el ID del Usuario 2 por su nombre de usuario
    user_id_2 = obtener_id_usuario_por_nombre(username_2)

    # Si no se encuentra el Usuario 2, termina la función
    if user_id_2 is None:
        print(f"No se encontró al usuario: {username_2}")
        return
    
    # Lista los archivos del Usuario 1 y obtiene los nombres de los archivos que el usuario quiere compartir
    archivos_a_compartir = listar_archivos_usuario_compartir()

    # Si no se seleccionó ningún archivo, termina la función
    if not archivos_a_compartir:
        print("No seleccionaste ningún archivo para compartir.")
        return

    # Obtén el ID del Usuario 1 por su nombre de usuario
    user_id_1 = obtener_user_id()

    # Si no se encuentra el Usuario 1, termina la función
    if user_id_1 is None:
        print(f"No se encontró al usuario: {bdd.nombre_usuario_global}")
        return

    # Para cada archivo que el usuario quiere compartir
    for nombre_archivo in archivos_a_compartir:
        # Obtén la clave AES cifrada del archivo del Usuario 1
        datos, clave_aes_cifrada = obtener_datos_archivo(user_id_1, nombre_archivo)

        # Descifra la clave AES con la clave privada del Usuario 1
        clave_aes = descifrar_clave_aes_con_rsa(clave_aes_cifrada)
        
        # Intenta descifrar los datos del archivo con AES
        try:
            datos_descifrados = descifrar_con_aes(datos, clave_aes)
            
            # Firmamos los datos descifrados
            firma = firmar_datos(datos_descifrados)

            # Elimina la extensión '.aes' del nombre del archivo
            nombre_archivo_descifrado = nombre_archivo.replace('.aes', '')

            # Guardamos los datos descifrados, la firma y el nombre del usuario que compartió el archivo en la base de datos
            cifrar_y_guardar_datos_en_db(user_id_2, datos_descifrados, nombre_archivo_descifrado, "./", firma, bdd.nombre_usuario_global)
            
            # cifrar_y_guardar_datos_en_db(user_id_2, datos_descifrados, nombre_archivo_descifrado, "./")
            
            print(f"Archivo {nombre_archivo_descifrado} compartido y cifrado.")
        except Exception as e:
            print(f"Error al descifrar {nombre_archivo}: {e}")


"""
Esta función se utiliza para obtener los detalles de todos los archivos asociados a un usuario específico en la base de datos.

Parámetros:
    user_id (int): El ID del usuario para el cual se deben obtener los detalles de los archivos.

Devuelve:
    detalles_archivos (list): Una lista de diccionarios, donde cada diccionario representa un archivo y contiene las siguientes claves:
        - 'archivo_id' (int): El ID del archivo.
        - 'nombre_archivo' (str): El nombre del archivo.
        - 'ruta_relativa' (str): La ruta relativa del archivo en el sistema de archivos.
        - 'user_id' (int): El ID del usuario que posee el archivo.

Funcionamiento:
    1. Se establece una conexión con la base de datos.
    2. Se ejecuta una consulta SQL para seleccionar las columnas archivo_id, nombre_archivo, ruta_relativa y user_id de la tabla 'archivos' donde el user_id coincide con el proporcionado.
    3. Se obtienen todos los resultados de la consulta, que se devuelven como una lista de tuplas.
    4. Se convierten los resultados en una lista de diccionarios para facilitar su manipulación.
    5. Se cierra la conexión a la base de datos.
    6. Se devuelve la lista de diccionarios.
"""
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
def guardar_archivo_en_db(user_id, nombre_archivo, nonce, tag, datos_cifrados, clave_aes_cifrada, ruta_relativa="./", firma=None, username_comparte=None):
    # Conecta con la base de datos
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    # Combina el nonce, el tag y los datos cifrados en una sola variable
    datos_completos = nonce + tag + datos_cifrados
    
    # Ejecuta la consulta SQL para insertar el archivo en la base de datos
    cursor.execute('''
        INSERT INTO archivos (user_id, nombre_archivo, datos, clave_AES_cifrada, ruta_relativa, firma, nombre_usuario_comparte)
        VALUES (?, ?, ?, ?, ?, ?, ?)''',
        (user_id, nombre_archivo, datos_completos, clave_aes_cifrada, ruta_relativa, firma, username_comparte))
    
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
    
def cifrar_y_guardar_datos_en_db(user_id, datos_archivo, nombre_archivo, ruta_directorio_destino, firma=None, username_comparte=None):
    # Cifra los datos del archivo con AES
    nonce, tag, datos_cifrados, clave_aes_cifrada = cifrar_con_aes(user_id, datos_archivo)
    
    # Añade la extensión '.aes' al nombre del archivo
    nombre_archivo_cifrado = nombre_archivo + '.aes'
    
    # Guarda el archivo cifrado en la base de datos
    guardar_archivo_en_db(user_id, nombre_archivo_cifrado, nonce, tag, datos_cifrados, clave_aes_cifrada, ruta_directorio_destino, firma, username_comparte)

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
def descargar_y_descifrar_archivo_individual(user_id, nombre_archivo, ruta_descarga, firma=None, username_comparte=None):
    # Obtiene los datos cifrados y la clave AES cifrada del archivo de la base de datos
    datos, clave_aes_cifrada = obtener_datos_archivo(user_id, nombre_archivo)

    # Descifra la clave AES con RSA
    clave_aes = descifrar_clave_aes_con_rsa(clave_aes_cifrada)

    # Intenta descifrar los datos del archivo con AES
    try:
        datos_descifrados = descifrar_con_aes(datos, clave_aes)
        
        if firma is not None:
            # Verifica la firma
            if verificar_firma(username_comparte, firma, datos_descifrados) is False:
                print("La firma del archivo no es válida.")
                return
        
        # Elimina la extensión '.aes' del nombre del archivo
        nombre_archivo_descifrado = nombre_archivo.replace('.aes', '')
        
        # Crea la ruta completa del archivo descifrado
        ruta_archivo_descifrado = os.path.join(ruta_descarga, nombre_archivo_descifrado)
        
        # Reemplaza los caracteres en la ruta de descarga
        ruta_archivo_descifrado = re.sub(r'[\\/]{2,}|[\\/]\\./', '/', ruta_archivo_descifrado)

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
    # Asegurarse de que ruta_carpeta termine con '/'
    if not ruta_carpeta.endswith('/'):
        ruta_carpeta += '/'
    # Obtener todos los archivos del usuario
    todos_los_archivos = obtener_detalles_archivos_usuario(user_id)

    # Crea la carpeta en el directorio de descargas si no existe
    ruta_descarga_carpeta = os.path.join(ruta_descarga, ruta_carpeta)
    os.makedirs(ruta_descarga_carpeta, exist_ok=True)

    # Filtrar para obtener solo los archivos dentro de la carpeta seleccionada y que terminan en '.aes'
    for archivo in todos_los_archivos:
        if archivo['ruta_relativa'].startswith(ruta_carpeta):
            if archivo['nombre_archivo'].endswith('.aes'):
                # Crea la ruta de descarga del archivo
                ruta_descarga_archivo = re.sub(r'[\\/]{2,}|[\\/]\\./', '/', ruta_descarga_carpeta)
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
    ruta_descarga = re.sub(r'[\\/]{2,}|[\\/]\\./', '/', ruta_descarga)
    
    # Crea el directorio de descarga si no existe
    os.makedirs(ruta_descarga, exist_ok=True)

    # Obtiene la lista de archivos del usuario
    elementos = listar_archivos_usuario()
    
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
                
                # Si el archivo tiene una firma, verifica la firma
                if elementos[idx]['firma'] is not None:
                    # Si el elemento es un archivo compartido, envia la firma y el nombre del usuario que lo compartió para verificar la firma y descargarlo
                    descargar_y_descifrar_archivo_individual(user_id, nombre_elemento, ruta_descarga, elementos[idx]['firma'], elementos[idx]['nombre_usuario_comparte'])
                else:
                    # Si el elemento es un archivo, lo descarga y descifra
                    descargar_y_descifrar_archivo_individual(user_id, nombre_elemento, ruta_descarga)
            else:
                # Si el elemento es una carpeta, descarga y descifra la carpeta completa
                descargar_y_descifrar_carpeta(user_id, elementos[idx]['ruta_relativa'], ruta_descarga)
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
El usuario puede realizar las siguientes acciones:

1. Crear archivo o carpeta: Llama a la función `crear_archivo_o_carpeta()`.
2. Subir archivo: Llama a la función `subir_archivo()`.
3. Subir carpeta: Llama a la función `subir_carpeta()`.
4. Descargar archivos: Llama a la función `descargar_y_descifrar_archivo()`.
5. Compartir archivo con otro usuario: Pide al usuario que ingrese el nombre del usuario con el que desea compartir el archivo y luego llama a la función `compartir_archivo_con_usuario(username_2)`.
6. Listar archivos: Llama a la función `listar_archivos_usuario()`, que devuelve una lista de archivos del usuario. Si no hay archivos disponibles, imprime un mensaje y termina la función. Si hay archivos disponibles, imprime la lista de archivos.
7. Salir: Termina el programa.

Si el usuario selecciona una opción no válida, imprime un mensaje de error y pide al usuario que intente nuevamente.

El menú de opciones se mantiene en ejecución hasta que el usuario decida salir.
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
        print("5. Compartir archivo con otro usuario")
        print("6. Listar archivos")
        print("7. Salir")
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
            # Si el usuario selecciona la opción de compartir archivo con otro usuario, llama a la función compartir_archivo_con_usuario
            username_2 = input("Ingrese el nombre de usuario con el que desea compartir el archivo: ")
            compartir_archivo_con_usuario(username_2)
        elif opcion == "6":
            # Si el usuario selecciona la opción de listar archivos, llama a la función listar_archivos_usuario
            elementos = listar_archivos_usuario()

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
        elif opcion == "7":
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