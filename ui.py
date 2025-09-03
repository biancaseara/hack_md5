import sys
import socket
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton,
    QLineEdit, QTextEdit, QStackedWidget, QListWidget, QListWidgetItem
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import string
# Certifique-se de que o arquivo hack_md5.py finalizado está na mesma pasta
import hack_md5

COORD_DISCOVERY_PORT = 9999
COORD_DISCOVERY_MSG = "COORDINATOR_DISCOVERY"

class DiscoveryThread(QThread):
    """Thread para descobrir coordenadores na rede via UDP Broadcast."""
    found = pyqtSignal(list)

    def run(self):
        results = []
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(3)
            try:
                sock.sendto(COORD_DISCOVERY_MSG.encode(), ('<broadcast>', COORD_DISCOVERY_PORT))
                while True:
                    try:
                        data, addr = sock.recvfrom(1024)
                        info = data.decode().split("|")
                        if len(info) == 2:
                            results.append({ "ip": addr[0], "port": info[0], "hash": info[1] })
                    except socket.timeout:
                        break
            except Exception as e:
                print(f"Erro na descoberta: {e}")

        self.found.emit(results)

class NodeThread(QThread):
    """Thread para rodar o nó (coordenador ou trabalhador) em background."""
    log_signal = pyqtSignal(str)
    
    def __init__(self, mode, config):
        super().__init__()
        self.mode = mode
        self.config = config
        self.node = None

    def run(self):
        ALPHABET = string.ascii_lowercase + string.digits
        port = int(self.config['port'])
        
        if self.mode == 'coordinator':
            self.node = hack_md5.Node(port, self.config['hash'], ALPHABET, is_coordinator=True)
            self.node.set_logger(self.log_signal.emit)
            # Adiciona o hash ao peer_list para que os trabalhadores possam obtê-lo
            self.node.peer_list[f"{self.node.host}:{self.node.port}"]['target_hash'] = self.config['hash']
            self.node.start_server()
            self.log_signal.emit(f"[COORDENADOR] Servidor iniciado em {self.node.host}:{port} com hash {self.config['hash']}")
        else: # Worker
            # Usa porta 0 para que o SO escolha uma porta livre
            self.node = hack_md5.Node(0, '', ALPHABET, is_coordinator=False)
            self.node.set_logger(self.log_signal.emit)
            self.node.start_server() # Inicia o servidor para receber mensagens de outros peers
            self.log_signal.emit(f"[TRABALHADOR] Servidor de trabalhador ouvindo em {self.node.host}:{self.node.port}")
            self.node.connect_to_peer(self.config['ip'], self.config['port'])

class Prompt(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("== HACK-MD5 DISTRIBUÍDO ==")
        self.setStyleSheet("""
            background-color: #111; 
            color: #33FF33; 
            font-family: 'Courier New', monospace; 
            font-size: 14px;
        """)
        self.setFixedSize(650, 450)
        self.thread = None
        self.menu_ui()

    def menu_ui(self):
        """Cria a UI inicial para escolher o modo."""
        self.stacked = QStackedWidget(self)
        main_menu = QWidget()
        layout = QVBoxLayout()
        label = QLabel("==[ HACK-MD5 CRACKER ]==")
        label.setAlignment(Qt.AlignCenter)
        label.setStyleSheet("font-size: 20px; font-weight: bold; padding: 10px;")
        layout.addWidget(label)

        btn_coord = QPushButton("1. Iniciar como Coordenador")
        btn_coord.clicked.connect(self.setup_coordinator_ui)
        btn_coord.setStyleSheet("background: #222; padding: 5px;")
        layout.addWidget(btn_coord)

        btn_worker = QPushButton("2. Iniciar como Trabalhador")
        btn_worker.clicked.connect(self.setup_worker_ui)
        btn_worker.setStyleSheet("background: #222; padding: 5px;")
        layout.addWidget(btn_worker)

        main_menu.setLayout(layout)
        self.stacked.addWidget(main_menu)
        self.setLayout(QVBoxLayout())
        self.layout().addWidget(self.stacked)

    def setup_coordinator_ui(self):
        """Cria a UI para configurar e iniciar o coordenador."""
        page = QWidget()
        layout = QVBoxLayout()
        ip = hack_md5.Utils.get_local_ip()

        layout.addWidget(QLabel(f"IP do Coordenador (Detectado): {ip}"))
        
        self.coord_port_input = QLineEdit("5000")
        self.coord_port_input.setPlaceholderText("Porta (ex: 5000)")
        layout.addWidget(self.coord_port_input)

        self.coord_hash_input = QLineEdit("e10adc3949ba59abbe56e057f20f883e") # Hash para "123456"
        self.coord_hash_input.setPlaceholderText("Hash MD5 Alvo")
        layout.addWidget(self.coord_hash_input)

        self.start_coord_btn = QPushButton("Iniciar Coordenador")
        self.start_coord_btn.clicked.connect(self.start_node)
        layout.addWidget(self.start_coord_btn)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output)
        
        page.setLayout(layout)
        self.stacked.addWidget(page)
        self.stacked.setCurrentWidget(page)

    def setup_worker_ui(self):
        """Cria a UI para descobrir e conectar a um coordenador."""
        page = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Coordenadores disponíveis na rede:"))

        self.coord_list_widget = QListWidget()
        layout.addWidget(self.coord_list_widget)

        btn_refresh = QPushButton("Procurar Coordenadores")
        btn_refresh.clicked.connect(self.discover_coordinators)
        layout.addWidget(btn_refresh)

        self.connect_worker_btn = QPushButton("Conectar ao Coordenador Selecionado")
        self.connect_worker_btn.clicked.connect(self.start_node)
        layout.addWidget(self.connect_worker_btn)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output)

        page.setLayout(layout)
        self.stacked.addWidget(page)
        self.stacked.setCurrentWidget(page)
        self.discover_coordinators()

    def discover_coordinators(self):
        """Inicia a thread de descoberta."""
        self.coord_list_widget.clear()
        self.log_output.append("> Procurando coordenadores na rede...")
        self.discovery_thread = DiscoveryThread()
        self.discovery_thread.found.connect(self.update_coordinator_list)
        self.discovery_thread.start()

    def update_coordinator_list(self, coords):
        """Atualiza a lista da UI com os coordenadores encontrados."""
        self.coord_list_widget.clear()
        if not coords:
            self.log_output.append("> Nenhum coordenador encontrado.")
            return
            
        for c in coords:
            item_text = f"IP: {c['ip']}:{c['port']} | Hash: {c['hash'][:15]}..."
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, c)
            self.coord_list_widget.addItem(item)
        self.log_output.append(f"> {len(coords)} coordenador(es) encontrado(s).")
        self.coord_list_widget.setCurrentRow(0)

    def start_node(self):
        """Inicia o nó (coordenador ou trabalhador) com base na UI atual."""
        sender = self.sender()
        # Verificação segura para determinar o modo
        mode = 'coordinator' if hasattr(self, 'start_coord_btn') and sender == self.start_coord_btn else 'worker'
        
        config = {}
        if mode == 'coordinator':
            port = self.coord_port_input.text().strip()
            hash_val = self.coord_hash_input.text().strip()
            if not port.isdigit() or len(hash_val) != 32:
                self.log_output.append("[ERRO] Porta inválida ou hash MD5 incorreto (deve ter 32 caracteres).")
                return
            config = {'port': port, 'hash': hash_val}
            self.start_coord_btn.setEnabled(False)
        else: # Worker
            selected = self.coord_list_widget.currentItem()
            if not selected:
                self.log_output.append("[ERRO] Nenhum coordenador selecionado.")
                return
            config = selected.data(Qt.UserRole)
            self.connect_worker_btn.setEnabled(False)
        
        self.thread = NodeThread(mode, config)
        self.thread.log_signal.connect(self.log_output.append)
        self.thread.start()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Prompt()
    window.show()
    sys.exit(app.exec_())