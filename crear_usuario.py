# crear_usuario.py
import json
from werkzeug.security import generate_password_hash
import os


def crear_usuario(usuario, contrasena):
    """Crea un usuario con contraseña hasheada"""
    archivo_json = 'usuarios.json'

    # Cargar usuarios existentes o crear nuevo diccionario
    if os.path.exists(archivo_json):
        with open(archivo_json, 'r', encoding='utf-8') as file:
            usuarios = json.load(file)
    else:
        usuarios = {}

    # Hashear la contraseña
    usuarios[usuario] = generate_password_hash(contrasena)

    # Guardar
    with open(archivo_json, 'w', encoding='utf-8') as file:
        json.dump(usuarios, file, indent=2, ensure_ascii=False)

    print(f" Usuario '{usuario}' creado con contraseña hasheada")
    print(f" Archivo: {archivo_json}")


def convertir_usuarios_existentes():
    """Convierte usuarios existentes de texto plano a hash"""
    archivo_json = 'usuarios.json'

    if not os.path.exists(archivo_json):
        print(" No se encontró el archivo usuarios.json")
        return

    # Hacer backup
    backup = f'usuarios_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    import shutil
    shutil.copy(archivo_json, backup)
    print(f" Backup creado: {backup}")

    # Cargar usuarios
    with open(archivo_json, 'r', encoding='utf-8') as file:
        usuarios_planos = json.load(file)

    # Convertir a hash
    usuarios_hash = {}
    for usuario, contrasena in usuarios_planos.items():
        usuarios_hash[usuario] = generate_password_hash(contrasena)
        print(f" Usuario '{usuario}' convertido a hash")

    # Guardar
    with open(archivo_json, 'w', encoding='utf-8') as file:
        json.dump(usuarios_hash, file, indent=2, ensure_ascii=False)

    print(f" {len(usuarios_hash)} usuarios convertidos a hash")


if __name__ == '__main__':
    from datetime import datetime

    print("=== GESTOR DE USUARIOS CON HASH ===\n")
    print("1. Crear nuevo usuario")
    print("2. Convertir usuarios existentes a hash")
    print("3. Salir")

    opcion = input("\nSelecciona una opción (1-3): ")

    if opcion == '1':
        print("\n--- NUEVO USUARIO ---")
        usuario = input("Usuario: ").strip().upper()
        contrasena = input("Contraseña: ").strip()
        if usuario and contrasena:
            crear_usuario(usuario, contrasena)
        else:
            print(" Usuario y contraseña son obligatorios")

    elif opcion == '2':
        print("\n--- CONVERTIR USUARIOS EXISTENTES ---")
        confirmar = input("¿Seguro? Se hará backup automático (s/n): ")
        if confirmar.lower() == 's':
            convertir_usuarios_existentes()
        else:
            print("Operación cancelada")

    else:
        print("¡Hasta luego!")