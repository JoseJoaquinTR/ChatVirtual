"""
Interfaz grafica del cliente.

Tiene tres pantallas:
  1. VentanaConexion: pide la IP del servidor y conecta.
  2. VentanaAuth: muestra dos pestanias (Login / Registro) y
     habla con el servidor para autenticar.
  3. ChatGUI: la ventana principal del chat.

Como las operaciones de red bloquean, se usan hilos para no
congelar la GUI. Los mensajes que llegan del servidor se ponen
en una cola y se procesan periodicamente con .after().
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import queue

from protocolo_tcp import ClienteTCP


# Paleta de colores (estilo oscuro con burbujas claras)

COLOR_FONDO = "#0f172a"
COLOR_FRAME = "#1e293b"
COLOR_CHAT_BG = "#ffffff"
COLOR_BURBUJA_SELF = "#dbeafe"
COLOR_BURBUJA_OTHER = "#e5e7eb"
COLOR_TEXTO_SYSTEM = "#9ca3af"


# Pantalla 1: conexion
class VentanaConexion(tk.Tk):
    """
    Primera ventana. Solo pide la IP del servidor y hace la conexion
    inicial (que incluye el handshake de claves).
    """

    def __init__(self):
        """
        Configura la ventana principal (titulo, tamanio, color de
        fondo) e instancia los widgets. Todavia no se conecta a
        ningun servidor: eso ocurre cuando el usuario presiona el
        boton 'Conectar'.
        """
        super().__init__()
        self.title("Conectar al servidor")
        self.geometry("360x180")
        self.resizable(False, False)
        self.configure(bg=COLOR_FONDO)

        self.cliente = None
        self._crear_widgets()

    def _crear_widgets(self):
        """
        Crea y posiciona los widgets de la ventana de conexion:
        titulo, campo para la IP y boton 'Conectar'.
        """
        marco = tk.Frame(self, bg=COLOR_FONDO, padx=20, pady=20)
        marco.pack(fill="both", expand=True)

        tk.Label(
            marco,
            text="Chat seguro - Conexion",
            bg=COLOR_FONDO, fg="white",
            font=("Segoe UI", 12, "bold")
        ).grid(row=0, column=0, columnspan=2, pady=(0, 15), sticky="w")

        tk.Label(
            marco, text="IP del servidor:",
            bg=COLOR_FONDO, fg="white", font=("Segoe UI", 10)
        ).grid(row=1, column=0, sticky="w", pady=5)

        self.entry_host = ttk.Entry(marco, width=22)
        self.entry_host.insert(0, "127.0.0.1")
        self.entry_host.grid(row=1, column=1, sticky="w", pady=5)

        ttk.Button(
            marco, text="Conectar",
            command=self.intentar_conectar
        ).grid(row=2, column=0, columnspan=2, pady=(20, 0))

    def intentar_conectar(self):
        """Crea el ClienteTCP y hace el handshake."""
        host = self.entry_host.get().strip()
        if not host:
            messagebox.showwarning("Falta IP", "Debes escribir la IP del servidor.")
            return

        self.cliente = ClienteTCP(host, 5000)
        if not self.cliente.conectar():
            messagebox.showerror(
                "Error",
                "No se pudo conectar.\n"
                "Verifica que el servidor este encendido y la IP sea correcta."
            )
            self.cliente = None
            return

        # Conexion lista, abrir pantalla de login
        self.withdraw()
        VentanaAuth(self, self.cliente)


# Pantalla 2: login / registro
class VentanaAuth(tk.Toplevel):
    """
    Maneja el login y registro. Mantiene el cliente ya conectado
    (el handshake de claves ya se hizo en VentanaConexion) y le
    envia los comandos /login o /registro.

    Las respuestas del servidor llegan asincronas, asi que se
    procesan en un hilo de escucha + cola.
    """

    def __init__(self, master, cliente):
        """
        Recibe el cliente ya conectado (con el handshake hecho) y
        prepara la ventana. Lanza el hilo de escucha del cliente y
        programa el polling de la cola, para procesar las respuestas
        del servidor sin congelar la GUI.

        Parametros:
          master  : ventana padre (VentanaConexion).
          cliente : instancia de ClienteTCP ya conectada.
        """
        super().__init__(master)
        self.master = master
        self.cliente = cliente
        self.title("Iniciar sesion")
        self.geometry("380x300")
        self.resizable(False, False)
        self.configure(bg=COLOR_FONDO)

        self.cola = queue.Queue()
        # Indica si ya estamos esperando una confirmacion de login
        self.esperando_login_de = None  # nombre de usuario o None

        self._crear_widgets()
        self.protocol("WM_DELETE_WINDOW", self.al_cerrar)

        # Usamos los callbacks del cliente para volcar a la cola
        self.cliente.on_message = self.cola.put
        self.cliente.on_disconnect = self._desconexion_remota

        # Lanzar hilo que recibe del servidor
        self.hilo_rx = threading.Thread(
            target=self.cliente.escuchar_mensajes, daemon=True
        )
        self.hilo_rx.start()

        self.after(100, self._procesar_cola)

    def _crear_widgets(self):
        """
        Arma el Notebook con dos pestanias (Iniciar sesion y Crear
        cuenta), sus campos de entrada y los botones correspondientes.
        Tambien crea una etiqueta de estado para mostrar mensajes
        del servidor (por ejemplo errores de login).
        """
        marco = tk.Frame(self, bg=COLOR_FONDO, padx=20, pady=20)
        marco.pack(fill="both", expand=True)

        # Pestanias
        self.notebook = ttk.Notebook(marco)
        self.notebook.pack(fill="both", expand=True)

        # --- Pestania login ---
        tab_login = tk.Frame(self.notebook, bg=COLOR_FONDO)
        self.notebook.add(tab_login, text="Iniciar sesion")

        tk.Label(tab_login, text="Usuario:", bg=COLOR_FONDO, fg="white",
                 font=("Segoe UI", 10)).grid(row=0, column=0, padx=5, pady=10, sticky="w")
        self.entry_user_login = ttk.Entry(tab_login, width=22)
        self.entry_user_login.grid(row=0, column=1, padx=5, pady=10)

        tk.Label(tab_login, text="Contrasenia:", bg=COLOR_FONDO, fg="white",
                 font=("Segoe UI", 10)).grid(row=1, column=0, padx=5, pady=10, sticky="w")
        self.entry_pass_login = ttk.Entry(tab_login, width=22, show="*")
        self.entry_pass_login.grid(row=1, column=1, padx=5, pady=10)

        ttk.Button(
            tab_login, text="Entrar",
            command=self.hacer_login
        ).grid(row=2, column=0, columnspan=2, pady=15)

        # --- Pestania registro ---
        tab_reg = tk.Frame(self.notebook, bg=COLOR_FONDO)
        self.notebook.add(tab_reg, text="Crear cuenta")

        tk.Label(tab_reg, text="Usuario:", bg=COLOR_FONDO, fg="white",
                 font=("Segoe UI", 10)).grid(row=0, column=0, padx=5, pady=10, sticky="w")
        self.entry_user_reg = ttk.Entry(tab_reg, width=22)
        self.entry_user_reg.grid(row=0, column=1, padx=5, pady=10)

        tk.Label(tab_reg, text="Contrasenia:", bg=COLOR_FONDO, fg="white",
                 font=("Segoe UI", 10)).grid(row=1, column=0, padx=5, pady=10, sticky="w")
        self.entry_pass_reg = ttk.Entry(tab_reg, width=22, show="*")
        self.entry_pass_reg.grid(row=1, column=1, padx=5, pady=10)

        ttk.Button(
            tab_reg, text="Registrar",
            command=self.hacer_registro
        ).grid(row=2, column=0, columnspan=2, pady=15)

        # Etiqueta de estado abajo
        self.lbl_estado = tk.Label(
            marco, text="", bg=COLOR_FONDO, fg=COLOR_TEXTO_SYSTEM,
            font=("Segoe UI", 9, "italic"), wraplength=320, justify="center"
        )
        self.lbl_estado.pack(pady=(10, 0))

    # --- Acciones ---
    def hacer_login(self):
        """
        Lee los campos de la pestania de login, valida que no esten
        vacios y envia el comando /login al servidor. La respuesta
        se procesara cuando llegue a la cola.
        """
        u = self.entry_user_login.get().strip()
        p = self.entry_pass_login.get()
        if not u or not p:
            self.lbl_estado.config(text="Ingresa usuario y contrasenia.")
            return
        self.esperando_login_de = u
        self.lbl_estado.config(text="Verificando credenciales...")
        self.cliente.enviar_login(u, p)

    def hacer_registro(self):
        """
        Lee los campos de la pestania de registro y envia el comando
        /registro al servidor. Si tiene exito, el servidor respondera
        con un mensaje y el usuario aun debera hacer login para entrar.
        """
        u = self.entry_user_reg.get().strip()
        p = self.entry_pass_reg.get()
        if not u or not p:
            self.lbl_estado.config(text="Ingresa usuario y contrasenia.")
            return
        self.lbl_estado.config(text="Registrando...")
        self.cliente.enviar_registro(u, p)

    # --- Manejo de mensajes del servidor ---
    def _procesar_cola(self):
        """
        Revisa los mensajes que llegaron del servidor y reacciona:
          - Si dice "Bienvenido, X" pasamos al chat.
          - Cualquier otra cosa la mostramos como estado.
        """
        try:
            while True:
                msg = self.cola.get_nowait()
                self._manejar_msg(msg.strip())
        except queue.Empty:
            pass
        finally:
            # Mientras la ventana exista, seguir revisando
            if self.winfo_exists():
                self.after(100, self._procesar_cola)

    def _manejar_msg(self, msg):
        """
        Decide que hacer con cada mensaje que llega del servidor
        durante la fase de autenticacion:
          - Si es la bienvenida ('Bienvenido, X.') significa que el
            login fue exitoso y se cambia a la ventana del chat.
          - Cualquier otro texto se muestra en la etiqueta de estado
            (errores, confirmaciones de registro, etc.).
        """
        # Confirmacion de login
        if msg.startswith("[Servidor] Bienvenido,"):
            # Extraer el nombre real con el que el servidor nos saludo
            nombre = msg[len("[Servidor] Bienvenido, "):].rstrip(".")
            self._ir_al_chat(nombre)
            return

        # Cualquier otro mensaje del servidor: mostrarlo como estado
        self.lbl_estado.config(text=msg)

    def _ir_al_chat(self, username):
        """Cierra esta ventana y abre la del chat."""
        self.lbl_estado.config(text="")
        # Quitamos los callbacks para que el ChatGUI los reasigne
        self.cliente.on_message = None
        self.cliente.on_disconnect = None
        self.withdraw()
        ChatGUI(self.master, self.cliente, username, ventana_auth=self)

    def _desconexion_remota(self):
        """Si el servidor nos cerro durante el login."""
        try:
            self.lbl_estado.config(text="Conexion perdida con el servidor.")
        except tk.TclError:
            pass

    def al_cerrar(self):
        """
        Se ejecuta cuando el usuario cierra la ventana de
        autenticacion (con la X o desde el sistema operativo).
        Cierra el cliente y termina la aplicacion.
        """
        try:
            self.cliente.cerrar()
        except Exception:
            pass
        self.master.destroy()


# Pantalla 3: chat
class ChatGUI(tk.Toplevel):
    """
    Ventana principal del chat. Recibe el cliente ya autenticado.
    """

    def __init__(self, master, cliente, username, ventana_auth=None):
        """
        Configura la ventana del chat con el usuario ya logueado.
        Reasigna los callbacks del cliente para que apunten a esta
        ventana y comienza a procesar la cola de mensajes.

        Parametros:
          master       : ventana raiz (VentanaConexion).
          cliente      : ClienteTCP ya conectado y autenticado.
          username     : nombre del usuario logueado.
          ventana_auth : referencia a la VentanaAuth para poder
                         destruirla al cerrar el chat.
        """
        super().__init__(master)
        self.master = master
        self.cliente = cliente
        self.username = username
        self.ventana_auth = ventana_auth

        self.title(f"Chat - {username}")
        self.geometry("780x560")
        self.minsize(640, 480)
        self.configure(bg=COLOR_FONDO)

        self.cola = queue.Queue()

        self._crear_widgets()
        self.protocol("WM_DELETE_WINDOW", self.al_cerrar)

        # Reasignamos callbacks al nuevo destino
        self.cliente.on_message = self.cola.put
        self.cliente.on_disconnect = self._desconexion_remota

        # En este punto el hilo de escucha ya esta corriendo
        # (lo lanzamos en VentanaAuth). No hace falta lanzarlo otra vez.

        self.after(100, self._procesar_cola)

        self._sistema(f"Conectado como {self.username}.")
        self._sistema(
            "Mensajes:\n"
            "  - Publico: escribe texto normal.\n"
            "  - Privado: @usuario mensaje.\n"
            "Comandos: /usuarios  /help  /salir"
        )

    # --- UI ---
    def _crear_widgets(self):
        """
        Arma toda la interfaz del chat:
          - Barra superior con el nombre del usuario y el boton
            'Desconectar'.
          - Area central de mensajes (Text con scrollbar).
          - Barra inferior con el campo de entrada y el boton
            'Enviar'.
        Tambien define los estilos visuales para distinguir los
        mensajes propios, ajenos y del sistema.
        """
        # Barra superior
        sup = tk.Frame(self, bg=COLOR_FRAME, height=45)
        sup.pack(side="top", fill="x")

        self.lbl_info = tk.Label(
            sup, text=f"Sesion: {self.username}",
            bg=COLOR_FRAME, fg="white",
            font=("Segoe UI", 10, "bold")
        )
        self.lbl_info.pack(side="left", padx=15, pady=10)

        ttk.Button(
            sup, text="Desconectar", command=self.al_cerrar
        ).pack(side="right", padx=15, pady=8)

        # Area de chat
        marco = tk.Frame(self, bg=COLOR_FONDO)
        marco.pack(fill="both", expand=True, padx=10, pady=5)

        self.text_chat = tk.Text(
            marco, state="disabled", wrap="word",
            bg=COLOR_CHAT_BG, bd=0, padx=10, pady=10,
            font=("Segoe UI", 10)
        )
        sb = ttk.Scrollbar(marco, orient="vertical", command=self.text_chat.yview)
        self.text_chat.configure(yscrollcommand=sb.set)
        self.text_chat.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        # Estilos de mensajes
        self.text_chat.tag_configure(
            "self", foreground="black", background=COLOR_BURBUJA_SELF,
            justify="right", lmargin1=80, lmargin2=80, rmargin=10, spacing3=4
        )
        self.text_chat.tag_configure(
            "other", foreground="black", background=COLOR_BURBUJA_OTHER,
            justify="left", lmargin1=10, lmargin2=10, rmargin=80, spacing3=4
        )
        self.text_chat.tag_configure(
            "system", foreground=COLOR_TEXTO_SYSTEM, justify="center",
            spacing3=4, font=("Segoe UI", 9, "italic")
        )

        # Barra inferior
        inf = tk.Frame(self, bg=COLOR_FRAME)
        inf.pack(side="bottom", fill="x")

        self.entry_msg = tk.Entry(inf, font=("Segoe UI", 10), bd=0)
        self.entry_msg.pack(side="left", fill="x", expand=True,
                            padx=(10, 5), pady=10)
        self.entry_msg.bind("<Return>", lambda e: (self.enviar(), "break"))

        ttk.Button(inf, text="Enviar", command=self.enviar).pack(
            side="right", padx=(5, 10), pady=10
        )

    # --- Envio ---
    def enviar(self):
        """
        Toma el texto del campo de entrada y decide como enviarlo:
          - '/salir' cierra la sesion.
          - Cualquier otro texto que empiece con '/' se envia como
            comando al servidor.
          - '@usuario texto' se envia como mensaje privado.
          - Cualquier otro caso es un mensaje publico.
        Al final limpia el campo para el siguiente mensaje.
        """
        msg = self.entry_msg.get().strip()
        if not msg:
            return

        if msg == "/salir":
            self.al_cerrar()
            return

        if msg.startswith("/"):
            self.cliente.enviar_comando(msg)
        elif msg.startswith("@"):
            try:
                destino, contenido = msg[1:].split(" ", 1)
                self.cliente.enviar_mensaje_privado(destino, contenido)
            except ValueError:
                messagebox.showwarning(
                    "Privado",
                    "Formato para privado: @usuario mensaje"
                )
                return
        else:
            self.cliente.enviar_mensaje_publico(msg)

        self.entry_msg.delete(0, tk.END)

    # --- Recepcion ---
    def _procesar_cola(self):
        """
        Saca mensajes de la cola (que el hilo de red va llenando) y
        los inserta en el area de chat. Se ejecuta periodicamente
        cada 100 ms con after(), para no bloquear el bucle de Tk.
        """
        try:
            while True:
                msg = self.cola.get_nowait()
                for linea in msg.splitlines():
                    linea = linea.rstrip()
                    if linea:
                        self._insertar(linea)
        except queue.Empty:
            pass
        finally:
            if self.winfo_exists():
                self.after(100, self._procesar_cola)

    def _insertar(self, linea):
        """Decide el tag visual segun la pinta de la linea."""
        tag = "system"

        if linea.startswith("[Servidor]") or linea.startswith("[Cliente]"):
            tag = "system"
        else:
            # Formato esperado: "[fecha] usuario: mensaje"
            try:
                fin = linea.index("]")
                resto = linea[fin + 1:].lstrip()
                nombre, sep, _ = resto.partition(":")
                nombre = nombre.strip()
                if sep:
                    if nombre == self.username:
                        tag = "self"
                    elif nombre.startswith("(privado de "):
                        tag = "other"
                    elif nombre.startswith("(privado para "):
                        tag = "self"
                    else:
                        tag = "other"
            except ValueError:
                tag = "system"

        self.text_chat.config(state="normal")
        self.text_chat.insert(tk.END, linea + "\n", (tag,))
        self.text_chat.see(tk.END)
        self.text_chat.config(state="disabled")

    def _sistema(self, texto):
        """
        Inserta un mensaje informativo local (sin pasar por el
        servidor) en el chat, con el prefijo '[Cliente]' para
        distinguirlo de los mensajes reales de la conversacion.
        """
        self.cola.put("[Cliente] " + texto)

    def _desconexion_remota(self):
        """Llamada cuando el servidor cierra la conexion."""
        try:
            self.cola.put("[Cliente] Conexion finalizada.")
        except Exception:
            pass

    def al_cerrar(self):
        """
        Maneja el cierre de la ventana del chat. Cierra el cliente
        (que avisa al servidor con /salir), destruye la ventana de
        autenticacion oculta y finalmente la raiz, terminando toda
        la aplicacion.
        """
        if self.cliente:
            try:
                self.cliente.cerrar()
            except Exception:
                pass
        # Cerrar todo: la ventana auth (oculta) y la principal
        try:
            if self.ventana_auth and self.ventana_auth.winfo_exists():
                self.ventana_auth.destroy()
        except tk.TclError:
            pass
        self.master.destroy()


# Punto de entrada
if __name__ == "__main__":
    app = VentanaConexion()
    app.mainloop()
