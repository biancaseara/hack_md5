from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, Button, Input, Checkbox, Log
from textual.containers import Grid, Container, Vertical, Horizontal
import threading
from hack_md5 import Node

class HackMD5App(App):
    CSS = """
    Grid {
        grid-size: 1 1;
        height: 100%;
        width: 100%;
        align: center middle;
    }
    #menu_box {
        width: 60;
        min-height: 36;
        padding: 2 2;
        border: solid $accent;
        background: $panel;
        align: center middle;
    }
    Vertical {
        align: center middle;
        width: 100%;
    }
    Horizontal {
        align: center middle;
        width: 100%;
    }
    #titulo {
        text-align: center;
        color: cyan;
        margin-bottom: 2;
        width: 100%;
    }
    Button {
        width: 100%;
        margin: 1 0;
    }
    Input {
        width: 100%;
        text-align: center;
    }
    Checkbox {
        width: auto;
        margin-right: 0;
        align: center middle;
    }
    #checkboxes {
        margin-bottom: 2;
        width: 100%;
        align: center middle;
    }
    #coordenador_options, #trabalhador_options {
        align: center middle;
        width: 100%;
    }
    #log {
        height: 10;
        margin-top: 2;
        overflow-y: auto;
        background: $boost;
        border: solid $accent;
        width: 100%;
        align: center middle;
    }
    """

    def __init__(self):
        super().__init__()
        self.selected_role = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Grid(
            Container(
                Vertical(
                    Static("Menu Hack_MD5", id="titulo"),
                    Horizontal(
                        Checkbox("Coordenador", id="coordenador"),
                        Checkbox("Trabalhador", id="trabalhador"),
                        id="checkboxes"
                    ),
                    Container(
                        Vertical(
                            Input(value="", placeholder="Porta para ouvir conexões", id="porta"),
                            Input(value="", placeholder="Hash alvo (MD5)", id="hash"),
                        ),
                        id="coordenador_options"
                    ),
                    Container(
                        Vertical(
                            Input(value="", placeholder="Endereço IP:Porta do coordenador", id="coordenador_addr"),
                        ),
                        id="trabalhador_options"
                    ),
                    Horizontal(
                        Button("Iniciar nó", id="start"),
                        Button("Sair", id="quit"),
                    ),
                    Log(id="log"),
                ),
                id="menu_box"
            )
        )
        yield Footer()

    def on_mount(self):
        self.node_thread = None
        self.node = None
        self.node_running = False
        self.update_fields()

    def update_fields(self):
        self.query_one("#coordenador_options").display = self.selected_role == "coordenador"
        self.query_one("#trabalhador_options").display = self.selected_role == "trabalhador"

    async def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.value:
            if event.checkbox.id == "coordenador":
                self.selected_role = "coordenador"
                self.query_one("#trabalhador", Checkbox).value = False
            elif event.checkbox.id == "trabalhador":
                self.selected_role = "trabalhador"
                self.query_one("#coordenador", Checkbox).value = False
        else:
            if not self.query_one("#coordenador", Checkbox).value and not self.query_one("#trabalhador", Checkbox).value:
                self.selected_role = None
        self.update_fields()

    def tui_log(self, msg):
        self.query_one("#log", Log).write(msg)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start":
            if self.node_running:
                self.tui_log("[INFO] Nó já está em execução.")
                return

            if not self.selected_role:
                self.tui_log("[ERROR] Selecione 'Coordenador' ou 'Trabalhador' antes de iniciar.")
                return

            if self.selected_role == "coordenador":
                porta = self.query_one("#porta", Input).value.strip()
                hash_alvo = self.query_one("#hash", Input).value.strip()
                if not porta.isdigit():
                    self.tui_log("[ERROR] Porta inválida.")
                    return
                if not hash_alvo:
                    self.tui_log("[ERROR] Informe o hash alvo.")
                    return
                porta = int(porta)
                self.node = Node(
                    porta,
                    hash_alvo,
                    is_coordinator=True,
                    is_worker=False
                )
                self.node.print = self.tui_log
                if hasattr(self.node.hash_cracker, "print"):
                    self.node.hash_cracker.print = self.tui_log
                self.node_thread = threading.Thread(target=self.run_node, daemon=True)
                self.node_thread.start()
                self.node_running = True
                self.tui_log(f"[INFO] Coordenador iniciado na porta {porta} com hash alvo {hash_alvo}.")

            elif self.selected_role == "trabalhador":
                coord_addr = self.query_one("#coordenador_addr", Input).value.strip()
                if ":" not in coord_addr:
                    self.tui_log("[ERROR] Endereço do coordenador deve ser no formato IP:porta.")
                    return
                ip, port = coord_addr.split(":")
                if not port.isdigit():
                    self.tui_log("[ERROR] Porta do coordenador inválida.")
                    return
                port = int(port)
                import random
                local_port = random.randint(4000, 9000)
                self.node = Node(
                    local_port,
                    "",  # hash alvo vazio para trabalhador
                    is_coordinator=False,
                    is_worker=True
                )
                self.node.print = self.tui_log
                if hasattr(self.node.hash_cracker, "print"):
                    self.node.hash_cracker.print = self.tui_log
                self.node_thread = threading.Thread(target=self.run_node, daemon=True)
                self.node_thread.start()
                self.node_running = True
                threading.Thread(target=self.node.connect_to_peer, args=(ip, port), daemon=True).start()
                self.tui_log(f"[INFO] Trabalhador iniciado e conectando ao coordenador {ip}:{port}.")

        elif event.button.id == "quit":
            self.exit()

    def run_node(self):
        try:
            self.node.start_server()
        except Exception as e:
            self.tui_log(f"[ERROR] Falha ao iniciar nó: {e}")

if __name__ == "__main__":
    HackMD5App().run()