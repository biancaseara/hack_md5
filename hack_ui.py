import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton,
    QLineEdit, QTextEdit, QStackedWidget
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import string
import hack_md5

class NodeThread(QThread):
    log_signal = pyqtSignal(str)

    def __init__(self, mode, ip, port, hash_value=None):
        super().__init__()
        self.mode = mode
        self.ip = ip
        self.port = int(port)
        self.hash_value = hash_value

    def run(self):
        ALPHABET = string.ascii_letters + string.digits + string.punctuation
        if self.mode == 'coordinator':
            node = hack_md5.Node(self.port, self.hash_value, ALPHABET, is_coordinator=True)
            node.set_logger(self.log_signal.emit)
            node.host = self.ip
            node.start_server()
            self.log_signal.emit(f"[COORDENADOR] Servidor iniciado em {self.ip}:{self.port} com hash {self.hash_value}")
        else:
            node = hack_md5.Node(self.port, '', ALPHABET)
            node.set_logger(self.log_signal.emit)
            node.host = hack_md5.Utils.get_local_ip()
            node.start_server()
            node.connect_to_peer(self.ip, int(self.port))
            self.log_signal.emit(f"[TRABALHADOR] Conectado ao coordenador em {self.ip}:{self.port}")

class Prompt(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("== HASH CRACKER ==")
        self.setStyleSheet("background-color: #111; color: #33FF33; font-family: 'Cascadia Code'; font-size: 14px;")
        self.setFixedSize(600, 420)
        self.menu_ui()

    def menu_ui(self):
        self.stacked = QStackedWidget(self)
        main_menu = QWidget()
        layout = QVBoxLayout()

        label = QLabel("==[ HACKER HASH CRACKER ]==")
        label.setAlignment(Qt.AlignCenter)
        label.setStyleSheet("font-size: 20px; font-weight: bold; font-family: 'Cascadia Code';")
        layout.addWidget(label)

        btn_coord = QPushButton("1. Coordenador")
        btn_coord.clicked.connect(self.setup_coordinator)
        btn_coord.setStyleSheet("background: #222; color: #33FF33; font-family: 'Cascadia Code';")
        layout.addWidget(btn_coord)

        btn_worker = QPushButton("2. Trabalhador")
        btn_worker.clicked.connect(self.setup_worker)
        btn_worker.setStyleSheet("background: #222; color: #33FF33; font-family: 'Cascadia Code';")
        layout.addWidget(btn_worker)

        main_menu.setLayout(layout)
        self.stacked.addWidget(main_menu)
        self.setLayout(QVBoxLayout())
        self.layout().addWidget(self.stacked)

    def setup_coordinator(self):
        page = QWidget()
        layout = QVBoxLayout()
        ip = hack_md5.Utils.get_local_ip()

        self.coord_ip = QLabel(f"IP Detectado: {ip}")
        self.coord_ip.setStyleSheet("font-weight: bold; font-family: 'Cascadia Code';")
        layout.addWidget(self.coord_ip)

        self.coord_port = QLineEdit()
        self.coord_port.setPlaceholderText("Porta para escutar (ex: 5000)")
        self.coord_port.setStyleSheet("font-family: 'Cascadia Code';")
        layout.addWidget(self.coord_port)

        self.coord_hash = QLineEdit()
        self.coord_hash.setPlaceholderText("Hash MD5 alvo")
        self.coord_hash.setStyleSheet("font-family: 'Cascadia Code';")
        layout.addWidget(self.coord_hash)

        btn_start = QPushButton("Iniciar Coordenador")
        btn_start.clicked.connect(self.start_coordinator)
        btn_start.setStyleSheet("font-family: 'Cascadia Code';")
        layout.addWidget(btn_start)

        self.coord_log = QTextEdit()
        self.coord_log.setReadOnly(True)
        self.coord_log.setStyleSheet("font-family: 'Cascadia Code';")
        layout.addWidget(self.coord_log)

        page.setLayout(layout)
        self.stacked.addWidget(page)
        self.stacked.setCurrentWidget(page)

    def setup_worker(self):
        page = QWidget()
        layout = QVBoxLayout()

        self.worker_ip = QLineEdit()
        self.worker_ip.setPlaceholderText("IP do Coordenador")
        self.worker_ip.setStyleSheet("font-family: 'Cascadia Code';")
        layout.addWidget(self.worker_ip)

        self.worker_port = QLineEdit()
        self.worker_port.setPlaceholderText("Porta do Coordenador (ex: 5000)")
        self.worker_port.setStyleSheet("font-family: 'Cascadia Code';")
        layout.addWidget(self.worker_port)

        btn_start = QPushButton("Conectar e Iniciar Trabalhador")
        btn_start.clicked.connect(self.start_worker)
        btn_start.setStyleSheet("font-family: 'Cascadia Code';")
        layout.addWidget(btn_start)

        self.worker_log = QTextEdit()
        self.worker_log.setReadOnly(True)
        self.worker_log.setStyleSheet("font-family: 'Cascadia Code';")
        layout.addWidget(self.worker_log)

        page.setLayout(layout)
        self.stacked.addWidget(page)
        self.stacked.setCurrentWidget(page)

    def start_coordinator(self):
        ip = hack_md5.Utils.get_local_ip()
        port = self.coord_port.text().strip()
        hash_value = self.coord_hash.text().strip()
        if not port.isdigit() or not hash_value:
            self.coord_log.append("[ERRO] Porta deve ser um número e hash não pode estar vazio.")
            return
        self.coord_log.append(f"> Iniciando como coordenador em {ip}:{port} para hash: {hash_value}")
        self.thread = NodeThread('coordinator', ip, port, hash_value)
        self.thread.log_signal.connect(self.coord_log.append)
        self.thread.start()

    def start_worker(self):
        ip = self.worker_ip.text().strip()
        port = self.worker_port.text().strip()
        if not ip or not port.isdigit():
            self.worker_log.append("[ERRO] IP do coordenador e porta válida são obrigatórios.")
            return
        self.worker_log.append(f"> Conectando ao coordenador {ip}:{port}")
        self.thread = NodeThread('worker', ip, port)
        self.thread.log_signal.connect(self.worker_log.append)
        self.thread.start()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Prompt()
    window.show()
    sys.exit(app.exec_())