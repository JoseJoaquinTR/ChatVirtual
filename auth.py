"""
Modulo de autenticacion.

Lee y escribe el archivo usuarios.json donde se guardan las credenciales de los usuarios
el hash es SHA-256 combinado con un salt aleatorio para cada usuario
"""

import json
import os
import hashlib
import secrets
import re


ARCHIVO_USUARIOS = "usuarios.json"

#solo permite nombres de usuario con letras, numeros y guion bajo para evitar inyeccion de codigo.
PATRON_USUARIO = re.compile(r"^[A-Za-z0-9_]{3,16}$")

# Longitud minima de contrasena.
LARGO_MIN_PASS = 4


# Validaciones
def usuario_es_valido(nombre):
    """
    Comprueba que el nombre de usuario respete el patron permitido.
    
    """
    if not isinstance(nombre, str):
        return False, "El nombre debe ser texto."
    if not PATRON_USUARIO.match(nombre):
        return False, ("El usuario debe tener entre 3 y 16 caracteres "
                       "y solo letras, numeros o guion bajo.")
    return True, ""


def password_es_valida(passwd):
    """
    Comprueba que la contrasena tenga el largo minimo y no contenga
    caracteres de control (saltos de linea, etc.)
    """
    if not isinstance(passwd, str):
        return False, "La contrasenia debe ser texto."
    if len(passwd) < LARGO_MIN_PASS:
        return False, f"La contrasenia debe tener al menos {LARGO_MIN_PASS} caracteres."
    # Rechazar caracteres de control
    for c in passwd:
        if ord(c) < 32:
            return False, "La contrasena contiene caracteres no permitidos."
    return True, ""


# Acceso al archivo
def _leer_archivo():
    """
    Carga el contenido de usuarios.json 
    """
    if not os.path.exists(ARCHIVO_USUARIOS):
        return {}
    try:
        with open(ARCHIVO_USUARIOS, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        # Si esta corrupto o ilegible
        return {}


def _guardar_archivo(datos):
    """Escribe el diccionario completo en usuarios.json."""
    with open(ARCHIVO_USUARIOS, "w", encoding="utf-8") as f:
        json.dump(datos, f, indent=2)


# Hash de contrasenas
def _hashear(passwd, salt):
    """
    Devuelve el hash SHA-256 hex del salt aleatorio y la contrasena

    Usar un salt aleatorio para cada usuario evita que dos usuarios con la
    misma contrasena tengan el mismo hash

    """
    mezcla = (salt + passwd).encode("utf-8")
    return hashlib.sha256(mezcla).hexdigest()


# Operaciones publicas
def existe_usuario(nombre):
    """Devuelve True si ya hay un registro con ese nombre."""
    datos = _leer_archivo()
    return nombre in datos


def registrar(nombre, passwd):
    """
    Registra a un nuevo usuario.

    Devuelve true si se registro correctamente o false si hubo algun problema (validacion fallida o usuario ya existente)
    """
    ok, motivo = usuario_es_valido(nombre)
    if not ok:
        return False, motivo
    ok, motivo = password_es_valida(passwd)
    if not ok:
        return False, motivo

    datos = _leer_archivo()
    if nombre in datos:
        return False, "El usuario ya existe."

    salt = secrets.token_hex(16)
    datos[nombre] = {
        "salt": salt,
        "hash": _hashear(passwd, salt)
    }
    _guardar_archivo(datos)
    return True, ""


def verificar(nombre, passwd):
    """
    Verifica las credenciales de un usuario existente

    Devuelve True si coinciden o False en caso contrario
    """
    ok, _ = usuario_es_valido(nombre)
    if not ok:
        return False
    ok, _ = password_es_valida(passwd)
    if not ok:
        return False

    datos = _leer_archivo()
    if nombre not in datos:
        return False
    registro = datos[nombre]
    salt = registro.get("salt", "")
    hash_guardado = registro.get("hash", "")
    return _hashear(passwd, salt) == hash_guardado
