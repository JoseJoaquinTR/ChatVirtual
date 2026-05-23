# ChatVirtual
Chat cliente-servidor en Python con TCP, cifrado asimétrico RSA-2048, autenticación con hash SHA-256 + salt, bitácora de eventos y soporte para múltiples usuarios. 
# Chat seguro TCP con cifrado asimétrico RSA

Aplicación de chat cliente-servidor desarrollada en Python. Permite la comunicación
entre múltiples usuarios mediante el protocolo TCP, con autenticación,
cifrado de extremo a extremo usando RSA y bitácora de eventos.

## Características

- Arquitectura cliente-servidor sobre TCP, puerto 5000
- Hasta 5 usuarios conectados simultáneamente
- Autenticación con registro e inicio de sesión
- Cifrado asimétrico RSA-2048 con padding OAEP/SHA-256
- Contraseñas almacenadas con hash SHA-256 + salt aleatorio
- Mensajes públicos y privados, con marca de fecha y hora
- Interfaz gráfica (Tkinter) y cliente por consola
- Bitácora de eventos con el módulo `logging`
- Validación y sanitización de todas las entradas

## Tecnologías

- Python 3.9+
- `cryptography` (RSA, OAEP, serialización PEM)
- `hashlib`, `secrets` (hashing y salt)
- `socket`, `threading`, `struct` (comunicación de bajo nivel)
- `tkinter` (interfaz gráfica)
- `logging` (bitácora)

## Estructura del proyecto
chat_seguro/
├── servidor.py         # Servidor TCP multihilo
├── cliente.py          # Cliente por consola
├── gui_cliente.py      # Cliente con interfaz gráfica
├── protocolo_tcp.py    # Tramas con prefijo de longitud y clase ClienteTCP
├── cripto.py           # Funciones RSA: generar, serializar, cifrar, descifrar
├── auth.py             # Registro, login, hash con salt
├── bitacora.py         # Configuración del logging
└── Leeme.txt           # Manual breve

## Instalación

```bash
pip install cryptography
```

## Uso

Iniciar el servidor:
```bash
python servidor.py
```

En otra terminal, iniciar un cliente gráfico:
```bash
python gui_cliente.py
```

O un cliente por consola:
```bash
python cliente.py
```

## Comandos del chat

| Comando | Acción |
|---|---|
| `texto normal` | Mensaje público a todos los conectados |
| `@usuario texto` | Mensaje privado al usuario indicado |
| `/usuarios` | Listar usuarios conectados |
| `/help` | Mostrar ayuda |
| `/salir` | Desconectarse del chat |

## Cómo funciona el cifrado

Al conectarse un cliente, antes de cualquier intercambio de datos, ambos
extremos negocian las claves:

1. El servidor envía su clave pública RSA al cliente.
2. El cliente genera su propio par y envía su clave pública al servidor.
3. A partir de ahí, cada lado cifra los mensajes con la clave pública
   del otro, y los descifra con su clave privada.
