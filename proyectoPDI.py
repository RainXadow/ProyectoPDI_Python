import os

# Datos de usuario y contraseña predeterminados
usuario_predeterminado = "usuario"
contrasena_predeterminada = "contrasena"

def autenticar_usuario():
    intentos = 3
    while intentos > 0:
        usuario = input("Usuario: ")
        contrasena = input("Contraseña: ")
        if usuario == usuario_predeterminado and contrasena == contrasena_predeterminada:
            print("Autenticación exitosa.")
            return True
        else:
            print("Autenticación fallida. Intentos restantes:", intentos - 1)
            intentos -= 1
    print("Demasiados intentos fallidos. Saliendo del programa.")
    return False

def gestionar_drive():
    if autenticar_usuario():
        drive_folder = "Drive"
        if not os.path.exists(drive_folder):
            os.mkdir(drive_folder)
        while True:
            print("\nMenú de opciones:")
            print("1. Crear archivo")
            print("2. Crear carpeta")
            print("3. Salir")
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
            elif opcion == "3":
                print("Saliendo del programa.")
                break
            else:
                print("Opción no válida. Intente nuevamente.")

gestionar_drive()
