import os
import tkinter as tk
from bdd import iniciar_sesion, seleccion, registrar_usuario, cifrar_con_aes, descifrar_con_aes
from tkinter import filedialog
import shutil
import json
import sys
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

    archivos = [f for f in os.listdir(carpeta_usuario) if os.path.isfile(os.path.join(carpeta_usuario, f))]
    print("Archivos disponibles:")
    for idx, archivo in enumerate(archivos):
        print(f"{idx + 1}. {archivo}")

    return archivos

# Descargamos y desciframos
def descargar_y_descifrar_archivo():
    # Cargar el user_id del archivo session_data.json
    with open('session_data.json', 'r') as file:
        session_data = json.load(file)
    user_id = session_data.get('user_uuid')

    archivos = listar_archivos_usuario(user_id)
    if not archivos:
        return

    eleccion = input("Ingrese los números de los archivos a descargar, separados por comas: ")
    indices_seleccionados = [int(x.strip()) - 1 for x in eleccion.split(',') if x.strip().isdigit()]

    for idx in indices_seleccionados:
        if 0 <= idx < len(archivos):
            archivo = archivos[idx]
            ruta_archivo = os.path.join(f'Servidor/{user_id}', archivo)

            # Leer el archivo cifrado
            with open(ruta_archivo, 'rb') as f:
                datos_cifrados = f.read()

            # Descifrar el archivo
            try:
                datos_descifrados = descifrar_con_aes(user_id, datos_cifrados)

                # Guardar el archivo descifrado
                ruta_archivo_descifrado = os.path.join("Descargas", os.path.basename(archivo).replace('.aes', ''))
                os.makedirs(os.path.dirname(ruta_archivo_descifrado), exist_ok=True)
                with open(ruta_archivo_descifrado, 'wb') as f:
                    f.write(datos_descifrados)

                print(f"Archivo {archivo} descargado y descifrado.")
            except Exception as e:
                print(f"Error al descifrar {archivo}: {e}")
        else:
            print(f"Índice {idx + 1} no válido.")


# Ciframos el archivo y lo subimos
def subir_archivo():
    # Cargar el user_id del archivo session_data.json
    with open('session_data.json', 'r') as file:
        session_data = json.load(file)
    user_id = session_data.get('user_uuid')

    # Carpeta de destino en el servidor
    carpeta_destino = f'Servidor/{user_id}'
    if not os.path.exists(carpeta_destino):
        os.makedirs(carpeta_destino)

    # Solicitar al usuario que seleccione los archivos
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)  # Nos aseguramos de que esté en primer plano
    archivos = filedialog.askopenfilenames()
    root.attributes('-topmost', False) # Desactivamos el primer plano
    root.destroy()
    
    # Verificar si se seleccionaron archivos
    if not archivos:
        print("No se seleccionó ningún archivo.")
        return

    # Cifrar y subir cada archivo
    for archivo in archivos:
        with open(archivo, 'rb') as f:
            datos_archivo = f.read()

        nonce, tag, datos_cifrados = cifrar_con_aes(user_id, datos_archivo)

        # Guardar el archivo cifrado en el servidor
        archivo_cifrado_nombre = os.path.basename(archivo) + '.aes'
        ruta_archivo_cifrado = os.path.join(carpeta_destino, archivo_cifrado_nombre)
        with open(ruta_archivo_cifrado, 'wb') as f:
            f.write(nonce)
            f.write(tag)
            f.write(datos_cifrados)

    print("Archivos subidos y cifrados con éxito.")

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