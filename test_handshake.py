
"""
Se conecta al servidor del chat y muestra la clave publica que
este envia como primer paso del handshake. Sirve como evidencia
de que la comunicacion comienza con un intercambio de claves
asimetricas y no en texto plano.
"""

import socket
import struct

s = socket.socket()
s.connect(("127.0.0.1", 5000))

tam = struct.unpack(">I", s.recv(4))[0]
datos = s.recv(tam)

print("Tamaño de la clave publica del servidor:", len(datos), "bytes")
print("Primeros 80 caracteres:")
print(datos[:80].decode())

s.close()