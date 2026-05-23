"""
Cliente TCP con cifrado asimetrico.

Protocolo de mensajes:
  Cada mensaje viaja con la siguiente estructura:
      4 bytes longitud ,datos

  Esto permite leer un mensaje completo sin depender de saltos
  de linea, lo cual es importante porque los datos cifrados son
  binarios y pueden contener cualquier byte.

  . El cliente genera su propio par de claves y envia su clave
     publica al servidor (sin cifrar todavia, igual que TLS hace
     con los certificados).
  . A partir de aqui:
       - Cliente cifra con clave_publica_servidor.
       - Servidor cifra con clave_publica_cliente.

Comandos de aplicacion:
  /login <usuario> <pass>     -> iniciar sesion
  /registro <usuario> <pass>  -> crear cuenta nueva
  /usuarios                   -> ver conectados
  /help                       -> ayuda
  /salir                      -> desconectarse
  @usuario texto              -> mensaje privado
  texto normal                -> mensaje publico
"""

import socket
import struct

import cripto


def enviar_trama(sock, datos):
    """
    Envia datos precedidos por su longitud en 4 bytes (big-endian).
    """
    cabecera = struct.pack(">I", len(datos))
    sock.sendall(cabecera + datos)


def recibir_exacto(sock, n):
    """
    Lee exactamente n bytes del socket. Si la conexion se cierra
    antes, devuelve None.
    """
    buffer = b""
    while len(buffer) < n:
        pedazo = sock.recv(n - len(buffer))
        if not pedazo:
            return None
        buffer += pedazo
    return buffer


def recibir_trama(sock):
    """
    Lee una trama completa: primero los 4 bytes de longitud y
    luego ese numero de bytes de datos. Devuelve los datos o None
    si la conexion se cerro.
    """
    cabecera = recibir_exacto(sock, 4)
    if cabecera is None:
        return None
    (largo,) = struct.unpack(">I", cabecera)
    if largo == 0:
        return b""
    return recibir_exacto(sock, largo)


# Cliente TCP
class ClienteTCP:
    """
    Cliente TCP con cifrado RSA.

    Mantiene la clave publica del servidor (para cifrar lo que
    se le envia) y su propia clave privada (para descifrar lo
    que el servidor envia).
    """

    def __init__(self, host, puerto, on_message=None, on_disconnect=None):
        """
        Inicializa el cliente. Todavia no abre la conexion.

        Parametros:
          host         : IP o nombre del servidor.
          puerto       : puerto TCP del servidor.
          on_message   : funcion opcional que se llama cada vez que
                         llega un mensaje del servidor (ya descifrado).
          on_disconnect: funcion opcional que se llama cuando se cierra
                         la conexion (por el servidor o por error).
        """
        self.host = host
        self.puerto = puerto
        self.on_message = on_message
        self.on_disconnect = on_disconnect

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conectado = False

        # Las claves se generan al conectar
        self.privada_cliente = None
        self.publica_servidor = None

    # Conexion 

    def conectar(self):
        """
        Se conecta al servidor y realiza el intercambio de claves
        publicas. NO hace login todavia: eso se hace despues con
        enviar_login() o enviar_registro().
        """
        try:
            self.sock.connect((self.host, self.puerto))
        except OSError as e:
            print(f"[TCP] Error al conectar: {e}")
            return False

        # Paso 1: recibir clave publica del servidor
        pem_servidor = recibir_trama(self.sock)
        if pem_servidor is None:
            return False
        try:
            self.publica_servidor = cripto.cargar_publica(pem_servidor)
        except Exception as e:
            print(f"[TCP] Clave del servidor invalida: {e}")
            return False

        # Paso 2: generar par propio y enviar la clave publica
        self.privada_cliente, publica_cliente = cripto.generar_par_claves()
        pem_cliente = cripto.serializar_publica(publica_cliente)
        try:
            enviar_trama(self.sock, pem_cliente)
        except OSError:
            return False

        self.conectado = True
        return True

    # Envio cifrado

    def _enviar_texto(self, texto):
        """
        Cifra el texto con la clave publica del servidor y lo envia
        como una trama.
        """
        if not self.conectado or self.publica_servidor is None:
            return
        datos = texto.encode("utf-8")
        try:
            cifrado = cripto.cifrar(datos, self.publica_servidor)
            enviar_trama(self.sock, cifrado)
        except OSError as e:
            print(f"[TCP] Error enviando: {e}")
            self.conectado = False

   

    def enviar_login(self, usuario, passwd):
        """Envia las credenciales para iniciar sesion."""
        self._enviar_texto(f"/login {usuario} {passwd}")

    def enviar_registro(self, usuario, passwd):
        """Envia los datos para crear una cuenta nueva."""
        self._enviar_texto(f"/registro {usuario} {passwd}")

    def enviar_mensaje_publico(self, mensaje):
        """Envia un mensaje a la sala publica."""
        self._enviar_texto(mensaje)

    def enviar_mensaje_privado(self, destinatario, mensaje):
        """Envia un mensaje privado a otro usuario."""
        self._enviar_texto(f"@{destinatario} {mensaje}")

    def enviar_comando(self, comando):
        """Envia un comando ya formateado (con su / inicial)."""
        self._enviar_texto(comando)

    # Recepcion en hilo aparte
    
    def escuchar_mensajes(self):
        """
        Bucle de recepcion. Lee tramas, las descifra con la clave
        privada propia y entrega el texto al callback on_message.
        """
        while self.conectado:
            try:
                trama = recibir_trama(self.sock)
            except OSError:
                break
            if trama is None:
                # Conexion cerrada por el otro lado
                break

            try:
                claro = cripto.descifrar(trama, self.privada_cliente).decode("utf-8")
            except Exception as e:
                print(f"[TCP] Error descifrando: {e}")
                continue

            if self.on_message:
                self.on_message(claro)
            else:
                # Modo consola sin callback: imprimir directo
                print(claro, end="" if claro.endswith("\n") else "\n")

        # Salida del bucle: la conexion termino
        self.conectado = False
        try:
            self.sock.close()
        except OSError:
            pass

        if self.on_disconnect:
            self.on_disconnect()

    def cerrar(self):
        """
        Cierra la conexion de manera ordenada: avisa al servidor
        con /salir, marca la conexion como inactiva y cierra el
        socket.
        """
        try:
            self._enviar_texto("/salir")
        except Exception:
            pass

        self.conectado = False
        try:
            self.sock.close()
        except OSError:
            pass

        # Para que un cierre voluntario no dispare on_disconnect
        # otra vez en la GUI.
        self.on_disconnect = None
