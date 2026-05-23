import threading
import sys

from protocolo_tcp import ClienteTCP

""" Pide un dato al usuario y no permite nulos, el usuario tiene que ingresar algo """
def pedir_no_vacio(mensaje):
    while True:
        valor = input(mensaje).strip()
        if valor:
            return valor

""" Este hilo es el que escucha los mensajes del servidor """
def hilo_escucha(cliente):
    try:
        cliente.escuchar_mensajes()
    except Exception as e:
        print(f"\n[Error en recepcion]: {e}")


def main():
    print("=== Cliente de chat seguro (TCP + RSA) ===")

    host = input("IP del servidor (vacio para 127.0.0.1): ").strip()
    if not host:
        host = "127.0.0.1"

    cliente = ClienteTCP(host, 5000)
    if not cliente.conectar():
        print("No se pudo conectar al servidor.")
        return

    print("Conexion establecida y claves intercambiadas.")
    print()
    print("1) Iniciar sesion")
    print("2) Registrarse")
    opcion = input("Elige (1/2): ").strip()

    usuario = pedir_no_vacio("Usuario: ")
    passwd = pedir_no_vacio("Contrasenia: ")

    t = threading.Thread(target=hilo_escucha, args=(cliente,), daemon=True)
    t.start()

    if opcion == "2":
        cliente.enviar_registro(usuario, passwd)
        print("Si el registro fue exitoso, ahora envia tu login.")
        usuario2 = pedir_no_vacio("Usuario para login: ")
        passwd2 = pedir_no_vacio("Contrasenia: ")
        cliente.enviar_login(usuario2, passwd2)
    else:
        cliente.enviar_login(usuario, passwd)

    print()
    print("Escribe mensajes. Comandos: /usuarios /help /salir")
    print("Privado: @usuario mensaje")
    print()

    try:
        while cliente.conectado:
            try:
                linea = input()
            except EOFError:
                break

            linea = linea.strip()
            if not linea:
                continue

            if linea == "/salir":
                cliente.cerrar()
                break

            if linea.startswith("/"):
                cliente.enviar_comando(linea)
            elif linea.startswith("@"):
                try:
                    destino, contenido = linea[1:].split(" ", 1)
                    cliente.enviar_mensaje_privado(destino, contenido)
                except ValueError:
                    print("Formato: @usuario mensaje")
            else:
                cliente.enviar_mensaje_publico(linea)
    except KeyboardInterrupt:
        cliente.cerrar()

    print("Saliendo...")
    sys.exit(0)


if __name__ == "__main__":
    main()
