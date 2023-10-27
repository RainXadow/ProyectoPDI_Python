import os
import tkinter as tk
from bdd import iniciar_sesion, seleccion, registrar_usuario
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
    
def subir_archivo():
    archivos = filedialog.askopenfilenames()
    carpeta_destino = f'Servidor/{user_id}'
    
    for archivo in archivos:
        shutil.copy(archivo, os.path.join(carpeta_destino, os.path.basename(archivo)))
    
    print("Archivos subidos con éxito.")

def subir_carpeta():
    carpeta_seleccionada = filedialog.askdirectory()
    carpeta_destino = f'Servidor/{user_id}'
    
    if not carpeta_seleccionada:
        print("No se seleccionó una carpeta.")
        return
    
    carpeta_nombre = os.path.basename(carpeta_seleccionada)
    carpeta_destino = os.path.join(carpeta_destino, carpeta_nombre)
    
    try:
        shutil.copytree(carpeta_seleccionada, carpeta_destino)
        print(f"Carpeta '{carpeta_nombre}' subida con éxito.")
    except FileExistsError:
        print(f"La carpeta '{carpeta_nombre}' ya existe en el destino.")
    except Exception as e:
        print(f"Error al subir la carpeta: {e}")

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
        print("5. Salir")
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