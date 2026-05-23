"""
Servidor TCP del chat seguro.

Caracteristicas:
  - Comunicacion cifrada con RSA en ambos sentidos.
  - Autenticacion con login/registro contra usuarios.json.
  - Maximo 5 usuarios conectados a la vez.
  - Mensajes publicos y privados, con marca de tiempo.
  - Bitacora de eventos en chat.log.

Cada conexion se atiende en un hilo independiente. La estructura
'usuarios' guarda los datos de los clientes ya autenticados.
"""

import socket
import threading
import struct
import re
from datetime import datetime

import cripto
import auth
from bitacora import obtener_logger
from protocolo_tcp import enviar_trama, recibir_trama


# Configuracion general


HOST = "0.0.0.0"
PUERTO = 5000
MAX_USUARIOS = 5

# Largo maximo de un mensaje publico/privado, para evitar abusos.
MAX_LARGO_MENSAJE = 500

log = obtener_logger("servidor")

# Diccionario: username -> {"sock": socket, "pub": clave_publica_cliente}
usuarios = {}
lock = threading.Lock()


# Utilidades
def timestamp():
    """Devuelve la fecha y hora actual como texto legible."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitizar(texto):
    """
    Limpia un texto recibido del cliente:
      - Elimina caracteres de control (ASCII < 32) excepto espacio.
      - Recorta espacios al inicio y final.
      - Limita el largo a MAX_LARGO_MENSAJE.
    """
    if not isinstance(texto, str):
        return ""
    # Eliminar caracteres de control
    limpio = "".join(c for c in texto if ord(c) >= 32 or c == " ")
    limpio = limpio.strip()
    if len(limpio) > MAX_LARGO_MENSAJE:
        limpio = limpio[:MAX_LARGO_MENSAJE]
    return limpio


# Envio cifrado a un usuario concreto
def enviar_a_usuario(username, texto):
    """
    Cifra 'texto' con la clave publica del usuario destino y se lo
    envia. Si el envio falla (por ejemplo el cliente se desconecto
    de manera abrupta), devuelve False.
    """
    with lock:
        info = usuarios.get(username)
    if not info:
        return False

    sock = info["sock"]
    pub = info["pub"]
    try:
        cifrado = cripto.cifrar(texto.encode("utf-8"), pub)
        enviar_trama(sock, cifrado)
        return True
    except OSError as e:
        log.warning("Fallo enviando a %s: %s", username, e)
        return False


def broadcast(texto, excepto=None):
    """
    Envia el texto a todos los usuarios autenticados.
    Si se pasa 'excepto', no se envia a ese usuario.
    """
    with lock:
        nombres = list(usuarios.keys())
    for u in nombres:
        if u == excepto:
            continue
        enviar_a_usuario(u, texto)


def eliminar_usuario(username):
    """Saca al usuario del registro de conectados."""
    with lock:
        usuarios.pop(username, None)
    log.info("Usuario desconectado: %s", username)


# Procesamiento de comandos ya autenticados

def procesar_linea(linea, username):
    """
    Procesa una linea ya descifrada y sanitizada de un usuario que
    ya hizo login. Devuelve True si la sesion debe continuar, o
    False si el cliente pidio salir.
    """
    if not linea:
        return True

    # ---------- Mensajes privados con @usuario ----------

    if linea.startswith("@"):
        try:
            destino, contenido = linea[1:].split(" ", 1)
        except ValueError:
            enviar_a_usuario(
                username,
                "[Servidor] Formato privado: @usuario mensaje"
            )
            return True

        destino = sanitizar(destino)
        contenido = sanitizar(contenido)
        if not destino or not contenido:
            enviar_a_usuario(username, "[Servidor] Mensaje privado vacio.")
            return True

        with lock:
            existe = destino in usuarios
        if not existe:
            enviar_a_usuario(
                username,
                f"[Servidor] El usuario '{destino}' no esta conectado."
            )
            return True

        marca = timestamp()
        # Al destinatario le llega indicando que es privado
        enviar_a_usuario(
            destino,
            f"[{marca}] (privado de {username}) {contenido}"
        )
        # Al remitente le llega un eco para confirmar
        enviar_a_usuario(
            username,
            f"[{marca}] (privado para {destino}) {contenido}"
        )
        log.info("Privado de %s a %s", username, destino)
        return True

    # ---------- Comandos de control ----------
    if linea.startswith("/"):
        if linea == "/salir":
            return False

        if linea == "/usuarios":
            with lock:
                lista = sorted(usuarios.keys())
            enviar_a_usuario(
                username,
                "[Servidor] Conectados: " + ", ".join(lista)
            )
            return True

        if linea == "/help":
            ayuda = (
                "[Servidor] Comandos disponibles:\n"
                "  /usuarios            ver usuarios conectados\n"
                "  /help                ver esta ayuda\n"
                "  /salir               desconectarse\n"
                "  @usuario mensaje     enviar privado\n"
                "  (texto)              enviar mensaje publico"
            )
            enviar_a_usuario(username, ayuda)
            return True

        # Cualquier otro comando: rechazar
        enviar_a_usuario(username, "[Servidor] Comando desconocido. Usa /help")
        return True

    # ---------- Mensaje publico ----------
    marca = timestamp()
    broadcast(f"[{marca}] {username}: {linea}")
    log.info("Publico de %s", username)
    return True


# Fase de autenticacion (antes de aceptar mensajes)

def autenticar(sock, pub_cliente):
    
    """
    Se queda en bucle hasta que el cliente envia un /login o /registro
    valido, o hasta que se desconecta.

    Devuelve el nombre de usuario en caso de exito, o None si hubo
    cualquier problema (mal formato, credenciales invalidas o cierre
    de la conexion).
    """

    def enviar(texto):
        """
        Envia un texto cifrado al cliente que se esta autenticando.
        Es una funcion local porque todavia no tenemos al usuario en
        el diccionario 'usuarios' (eso pasa hasta que el login es
        exitoso), asi que no podemos usar enviar_a_usuario().
        """
        try:
            cif = cripto.cifrar(texto.encode("utf-8"), pub_cliente)
            enviar_trama(sock, cif)
        except OSError:
            pass

    # Damos pocas oportunidades para evitar abuso.
    intentos = 0
    MAX_INTENTOS = 5

    # Importamos aqui la clave privada del servidor para descifrar.
    # Se inyecta desde el entorno global del modulo.
    global PRIV_SERVIDOR

    while intentos < MAX_INTENTOS:
        try:
            trama = recibir_trama(sock)
        except OSError:
            return None
        if trama is None:
            return None

        try:
            linea = cripto.descifrar(trama, PRIV_SERVIDOR).decode("utf-8")
        except Exception:
            enviar("[Servidor] No se pudo procesar el mensaje.")
            intentos += 1
            continue

        linea = sanitizar(linea)

        # ----- Registro -----
        if linea.startswith("/registro "):
            partes = linea.split(" ", 2)
            if len(partes) != 3:
                enviar("[Servidor] Uso: /registro usuario contrasenia")
                intentos += 1
                continue
            _, usuario, passwd = partes
            ok, motivo = auth.registrar(usuario, passwd)
            if not ok:
                enviar(f"[Servidor] No se pudo registrar: {motivo}")
                log.info("Intento de registro fallido para '%s': %s", usuario, motivo)
                intentos += 1
                continue
            log.info("Nuevo usuario registrado: %s", usuario)
            enviar(f"[Servidor] Usuario {usuario} registrado. Ahora haz /login.")
            continue

        # ----- Login -----
        if linea.startswith("/login "):
            partes = linea.split(" ", 2)
            if len(partes) != 3:
                enviar("[Servidor] Uso: /login usuario contrasenia")
                intentos += 1
                continue
            _, usuario, passwd = partes

            if not auth.verificar(usuario, passwd):
                enviar("[Servidor] Usuario o contrasenia incorrectos.")
                log.warning("Login fallido para usuario '%s'", usuario)
                intentos += 1
                continue

            # Verificar que no este ya conectado y haya cupo
            with lock:
                if usuario in usuarios:
                    enviar("[Servidor] Esa cuenta ya esta conectada.")
                    intentos += 1
                    continue
                if len(usuarios) >= MAX_USUARIOS:
                    enviar("[Servidor] Servidor lleno (max 5 usuarios).")
                    log.warning("Conexion rechazada por cupo lleno: %s", usuario)
                    return None
                usuarios[usuario] = {"sock": sock, "pub": pub_cliente}

            enviar(f"[Servidor] Bienvenido, {usuario}.")
            log.info("Login exitoso: %s", usuario)
            return usuario

        # ----- Cualquier otra cosa antes de loguearse -----
        enviar("[Servidor] Debes hacer /login usuario pass o /registro usuario pass.")
        intentos += 1

    # Se acabaron los intentos
    return None


# ---------------------------------------------------------------------
# Hilo por cliente
# ---------------------------------------------------------------------
def manejar_cliente(sock, addr):
    """
    Atiende una conexion entrante de principio a fin:
      1. Hace el handshake de claves.
      2. Pide login/registro hasta que se autentique.
      3. Procesa mensajes y comandos hasta /salir o desconexion.
    """
    log.info("Conexion entrante desde %s:%s", addr[0], addr[1])
    username = None
    try:
        # Paso 1: enviar al cliente nuestra clave publica
        pem = cripto.serializar_publica(PUB_SERVIDOR)
        enviar_trama(sock, pem)

        # Paso 2: recibir la clave publica del cliente
        pem_cliente = recibir_trama(sock)
        if pem_cliente is None:
            log.info("El cliente %s cerro antes del handshake", addr)
            return
        pub_cliente = cripto.cargar_publica(pem_cliente)

        # Paso 3: autenticar
        username = autenticar(sock, pub_cliente)
        if username is None:
            log.info("Autenticacion fallida desde %s", addr)
            return

        # Avisar al resto que llego alguien
        broadcast(f"[{timestamp()}] {username} se ha unido al chat.",
                  excepto=username)

        # Paso 4: bucle principal del cliente
        while True:
            try:
                trama = recibir_trama(sock)
            except OSError:
                break
            if trama is None:
                break

            try:
                texto = cripto.descifrar(trama, PRIV_SERVIDOR).decode("utf-8")
            except Exception as e:
                log.warning("Mensaje no descifrable de %s: %s", username, e)
                continue

            linea = sanitizar(texto)
            seguir = procesar_linea(linea, username)
            if not seguir:
                break

    except Exception as e:
        log.exception("Error atendiendo a %s: %s", addr, e)
    finally:
        if username:
            eliminar_usuario(username)
            broadcast(f"[{timestamp()}] {username} ha salido del chat.")
        try:
            sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------
# Arranque
# ---------------------------------------------------------------------
# El par de claves del servidor se genera una sola vez al inicio.
# Se exponen como variables de modulo para que los hilos las usen.
PRIV_SERVIDOR = None
PUB_SERVIDOR = None


def iniciar():
    """Crea el socket de escucha y atiende conexiones en un bucle."""
    global PRIV_SERVIDOR, PUB_SERVIDOR

    log.info("Generando par de claves RSA del servidor...")
    PRIV_SERVIDOR, PUB_SERVIDOR = cripto.generar_par_claves()
    log.info("Claves generadas.")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PUERTO))
    s.listen()

    log.info("Servidor escuchando en %s:%s (max %d usuarios)",
             HOST, PUERTO, MAX_USUARIOS)
    print(f"[Servidor] Escuchando en {HOST}:{PUERTO}")
    print("[Servidor] Para detener: Ctrl+C")

    try:
        while True:
            sock, addr = s.accept()
            t = threading.Thread(
                target=manejar_cliente,
                args=(sock, addr),
                daemon=True
            )
            t.start()
    except KeyboardInterrupt:
        print("\n[Servidor] Cerrando...")
        log.info("Servidor detenido por el operador")
    finally:
        try:
            s.close()
        except OSError:
            pass


if __name__ == "__main__":
    iniciar()
