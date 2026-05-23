from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


# Tamanio de la clave
TAM_CLAVE = 2048

MAX_BLOQUE = 190

""" Genera la llave privada y la llave publica y las
    devuelve como par """
def generar_par_claves():
    privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=TAM_CLAVE
    )
    publica = privada.public_key()
    return privada, publica

""" Convierte la llave publica en bytes, y la convierte a formato PEM """
def serializar_publica(clave_publica):
    return clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

""" Convierte los bytes que estan en formato PEM a una clave publica,
    es para cuando alguien recibe una llave publica """
def cargar_publica(datos_pem):
    return serialization.load_pem_public_key(datos_pem)

""" Parte el mensaje en pedazos de 190 bytes para cifrarlos por separado
    y al final une estos pedazos cifrados y los devuelve """
def cifrar(mensaje_bytes, clave_publica):
    bloques_cifrados = []
    for inicio in range(0, len(mensaje_bytes), MAX_BLOQUE):
        bloque = mensaje_bytes[inicio:inicio + MAX_BLOQUE]
        cifrado = clave_publica.encrypt(
            bloque,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        bloques_cifrados.append(cifrado)
    return b"".join(bloques_cifrados)

""" recorre los bloques que tienen un tamanio de 256 bytes para irlos
    descifrando y al final los une y los devuelve """
def descifrar(datos_cifrados, clave_privada):
    tam_bloque = TAM_CLAVE // 8
    partes = []
    for inicio in range(0, len(datos_cifrados), tam_bloque):
        bloque = datos_cifrados[inicio:inicio + tam_bloque]
        plano = clave_privada.decrypt(
            bloque,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        partes.append(plano)
    return b"".join(partes)
