from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, Button, Input, Checkbox, Log
from textual.containers import Grid, Container, Vertical, Horizontal
import threading
from hack_md5 import Node

class ExclusiveCheckbox(Checkbox):
    """Checkbox that triggers deselection of others in a group."""
    def __init__(self, label: str, group: str, **kwargs):
        super().__init__(label, **kwargs)
        self.group = group

class HackMD5App(App):
    CSS = """
    Grid {
        grid-size: 1 1;
        height: 100%;
        width: 100%;
        align: center middle;
    }
    #menu_box {
        width: 50;
        min-height: 32;
        padding: 2 2;
        border: solid $accent;
        background: $panel;
        align: center middle;
    }
    #titulo {
        text-align: center;
        color: cyan;
        margin-bottom: 2;
    }
    Button {
        width: 100%;
        margin: 1 0;
    }
    Input {
        width: 100%;
    }
    Checkbox {
        width: auto;
        margin-right: 0;
    }
    #checkboxes {
        margin-bottom: 1;
        width: 100%;
        /* gap: 0; removido pois não é suportado */
    }
    #log {
        height: 10;
        margin-top: 2;
        overflow-y: auto;
        background: $boost;
        border: solid $accent;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        yield Grid(
            Container(
                Vertical(
                    Static("Menu Hack_MD5", id="titulo"),
                    Input(value="", placeholder="Porta", id="porta"),
                    Input(value="", placeholder="Hash alvo (MD5)", id="hash"),
                    Horizontal(
                        ExclusiveCheckbox("Coordenador", group="role", id="coordenador"),
                        ExclusiveCheckbox("Trabalhador", group="role", id="trabalhador"),
                        id="checkboxes"
                    ),
                    Horizontal(
                        Button("Iniciar nó", id="start"),
                        Button("Conectar peer", id="connect"),
                        Button("Sair", id="quit"),
                    ),
                    Input(value="", placeholder="Host:Port peer", id="peer_addr"),
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

    def tui_log(self, msg):
        self.query_one("#log", Log).write(msg)

    async def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        # Exclusividade: só uma marcada por vez.
        if isinstance(event.checkbox, ExclusiveCheckbox) and event.value:
            for other_id in ["coordenador", "trabalhador"]:
                if event.checkbox.id != other_id:
                    other = self.query_one(f"#{other_id}", ExclusiveCheckbox)
                    if other.value:
                        other.value = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start":
            if self.node_running:
                self.tui_log("[INFO] Nó já está em execução.")
                return

            porta = int(self.query_one("#porta", Input).value.strip())
            hash_alvo = self.query_one("#hash", Input).value.strip()
            is_coordinator = self.query_one("#coordenador", Checkbox).value
            is_worker = self.query_one("#trabalhador", Checkbox).value

            if not is_coordinator and not is_worker:
                self.tui_log("[ERROR] Selecione 'Coordenador' ou 'Trabalhador'.")
                return

            self.node = Node(
                porta,
                hash_alvo,
                is_coordinator=is_coordinator,
                is_worker=is_worker
            )

            self.node.print = self.tui_log
            if hasattr(self.node.hash_cracker, "print"):
                self.node.hash_cracker.print = self.tui_log
            self.node_thread = threading.Thread(target=self.run_node, daemon=True)
            self.node_thread.start()
            self.node_running = True
            tipo = "Coordenador" if is_coordinator else "Trabalhador"
            self.tui_log(f"[INFO] Nó iniciado na porta {porta} como {tipo}.")

        elif event.button.id == "connect":
            if not self.node_running or not self.node:
                self.tui_log("[ERROR] Inicie o nó antes de conectar a peers.")
                return
            peer_addr = self.query_one("#peer_addr", Input).value.strip()
            if ":" not in peer_addr:
                self.tui_log("[ERROR] Endereço do peer no formato host:port")
                return
            host, port = peer_addr.split(":")
            try:
                port = int(port)
                threading.Thread(target=self.node.connect_to_peer, args=(host, port), daemon=True).start()
                self.tui_log(f"[INFO] Conectando a peer {peer_addr} ...")
            except Exception as e:
                self.tui_log(f"[ERROR] Falha ao conectar a peer: {e}")

        elif event.button.id == "quit":
            self.exit()

    def run_node(self):
        try:
            self.node.start_server()
        except Exception as e:
            self.tui_log(f"[ERROR] Falha ao iniciar nó: {e}")

if __name__ == "__main__":
    HackMD5App().run()