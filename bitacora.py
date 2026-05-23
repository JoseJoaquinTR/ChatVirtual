"""
Modulo de bitacora de seguridad del sistema

Centraliza la configuracion del logging para que tanto el servidor como las otras partes del proyecto escriban en el mismo archivo.

"""

import logging
import os


# Nombre del archivo de bitacora
ARCHIVO_LOG = "chat.log"


def obtener_logger(nombre):
    """
    Devuelve un logger ya configurado.

    si es la primera llamada agrega un manejador que escrive en el archivo chat.log y otro que escribe en la consola. 
    
    De esta forma los eventos quedan guardados y a la vez se pueden ver mientras se ejecuta el servidor.
    """
    logger = logging.getLogger(nombre)

    #si ya existe entonces evitamos duplicados
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    formato = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Manejador a archivo
    fh = logging.FileHandler(ARCHIVO_LOG, encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(formato)
    logger.addHandler(fh)

    # Manejador a consola
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formato)
    logger.addHandler(ch)

    return logger


def ruta_log():
    """Devuelve la ruta absoluta del archivo de bitacora."""
    return os.path.abspath(ARCHIVO_LOG)
