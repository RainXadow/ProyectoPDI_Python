import os
import unittest

import proyectoPDI


class TestProyectoPDI(unittest.TestCase):

    def setUp(self):
        self.user_id = 1
        self.ruta_descarga = os.path.join(str(self.user_id), "Descargas")

    def test_descargar_y_descifrar_archivo(self):
        # Asegurarse de que la carpeta de descarga existe
        os.makedirs(self.ruta_descarga, exist_ok=True)

        # Llamar a la función que se está probando
        proyectoPDI.descargar_y_descifrar_archivo()

        # Comprobar que se han descargado y descifrado los archivos
        # Esto dependerá de cómo esté implementada la función `descargar_y_descifrar_archivo_individual`
        # y `descargar_y_descifrar_carpeta`

if __name__ == "__main__":
    unittest.main()