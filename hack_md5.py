import socket
import threading
import json
import time
import hashlib
import itertools
import string
import sys

class Utils:
    @staticmethod
    def send_message(target_host, target_port, message):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_host, target_port))
            s.sendall(json.dumps(message).encode('utf-8'))
            s.close()
            return True
        except Exception as e:
            print(f"[ERROR] Falha ao enviar mensagem para {target_host}:{target_port}: {e}")
            return False

    @staticmethod
    def get_local_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

class HashCracker:
    def __init__(self, alphabet, logger):
        self.alphabet = alphabet
        self.found_word = None
        self.logger = logger

    def process_combinations(self, char_count, target_hash):
        if self.found_word is not None:
            return False

        self.logger(f"[DEBUG] Testando combinações de {char_count} caracteres...")
        for p in itertools.product(self.alphabet, repeat=char_count):
            word = "".join(p)
            word_hash = hashlib.md5(word.encode()).hexdigest()
            if word_hash == target_hash:
                self.found_word = word
                return True

        self.logger(f"[DEBUG] Nenhuma palavra encontrada com {char_count} caracteres.")
        return False

class Node:
    def __init__(self, port, target_hash, alphabet, is_coordinator=False):
        self.host = Utils.get_local_ip()
        self.port = port
        self.peer_list = {f"{self.host}:{self.port}": {"host": self.host, "port": self.port, "is_coordinator": is_coordinator}}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True
        self.lamport_clock = 0
        self.is_coordinator = is_coordinator
        self.shared_char_count = 1
        self.target_hash = target_hash
        self.ui_logger = print
        self.hash_cracker = HashCracker(alphabet, self.ui_logger)
        self.in_critical_section = False
        self.requesting_critical_section = False
        self.replies_received = 0
        self.deferred_replies = []
        self.request_time = 0

    def set_logger(self, logger):
        self.ui_logger = logger
        self.hash_cracker.logger = logger

    def log(self, message):
        self.ui_logger(message)

    def start_server(self):
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            self.log(f"[DEBUG] Servidor ouvindo em {self.host}:{self.port}")
            accept_thread = threading.Thread(target=self.accept_connections, daemon=True)
            accept_thread.start()
            if self.is_coordinator:
                self.log("[DEBUG] Este nó é o coordenador do sistema.")
        except Exception as e:
            self.log(f"[ERROR] Erro ao iniciar servidor: {e}")
            self.running = False

    def accept_connections(self):
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                self.log(f"[DEBUG] Conexão recebida de {addr}")
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                client_thread.start()
            except Exception as e:
                self.log(f"[ERROR] Erro ao aceitar conexão: {e}")
                self.running = False

    def handle_client(self, conn, addr):
        try:
            data = conn.recv(1024).decode('utf-8')
            message = json.loads(data)
            received_clock = message.get('clock', 0)
            self.lamport_clock = max(self.lamport_clock, received_clock) + 1
            self.log(f"[DEBUG] Lamport clock atualizado: {self.lamport_clock}")

            if message['type'] == 'new_peer':
                peer_address = f"{message['host']}:{message['port']}"
                if peer_address not in self.peer_list:
                    self.peer_list[peer_address] = {"host": message['host'], "port": message['port'], "is_coordinator": message.get("is_coordinator", False)}
                    self.log(f"[DEBUG] Novo peer adicionado: {peer_address}")
                response = {"type": "peer_list", "peers": self.peer_list, "clock": self.lamport_clock}
                conn.sendall(json.dumps(response).encode('utf-8'))

            elif message['type'] == 'peer_list':
                self.update_peer_list(message['peers'])

            elif message['type'] == 'request':
                request_clock = message['clock']
                requesting_peer_id = message['peer_id']
                higher_priority = (request_clock < self.request_time) or \
                                  (request_clock == self.request_time and requesting_peer_id < f"{self.host}:{self.port}")
                not_busy = not self.requesting_critical_section and not self.in_critical_section
                if not_busy or (self.requesting_critical_section and higher_priority):
                    reply_message = {"type": "reply", "clock": self.lamport_clock, "peer_id": f"{self.host}:{self.port}"}
                    Utils.send_message(self.peer_list[requesting_peer_id]['host'], self.peer_list[requesting_peer_id]['port'], reply_message)
                else:
                    self.deferred_replies.append(requesting_peer_id)
                    self.log(f"[DEBUG] Adiou REPLY para {requesting_peer_id}")

            elif message['type'] == 'reply':
                self.replies_received += 1
                if self.replies_received >= len(self.peer_list) - 1:
                    self.enter_critical_section()

            elif message['type'] == 'found_word':
                self.hash_cracker.found_word = message['word']
                self.log(f"[SUCCESS] Palavra encontrada por outro nó: {self.hash_cracker.found_word}")

            elif message['type'] == 'get_char_count_request':
                if self.is_coordinator:
                    response_message = {"type": "char_count_reply", "char_count": self.shared_char_count}
                    self.shared_char_count += 1
                    conn.sendall(json.dumps(response_message).encode('utf-8'))

            else:
                self.log(f"[DEBUG] Mensagem recebida: {message}")
        except Exception as e:
            self.log(f"[ERROR] Erro ao lidar com cliente: {e}")
        finally:
            conn.close()

    def connect_to_peer(self, peer_host, peer_port):
        try:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect((peer_host, peer_port))
            self.log(f"[DEBUG] Conectado a {peer_host}:{peer_port}")
            self.lamport_clock += 1
            message = {"type": "new_peer", "host": self.host, "port": self.port, "is_coordinator": self.is_coordinator, "clock": self.lamport_clock}
            peer_socket.sendall(json.dumps(message).encode('utf-8'))
            response_data = peer_socket.recv(4096).decode('utf-8')
            response = json.loads(response_data)
            if response['type'] == 'peer_list':
                self.update_peer_list(response['peers'])
                if not self.is_coordinator:
                    threading.Thread(target=self.request_access, daemon=True).start()
        except Exception as e:
            self.log(f"[ERROR] Erro ao conectar a peer: {e}")
        finally:
            peer_socket.close()

    def update_peer_list(self, new_peers):
        for peer_address, peer_info in new_peers.items():
            if peer_address not in self.peer_list:
                self.peer_list[peer_address] = peer_info
                self.log(f"[DEBUG] Peer adicionado: {peer_address}")

    def request_access(self):
        if self.hash_cracker.found_word is None:
            self.requesting_critical_section = True
            self.lamport_clock += 1
            self.replies_received = 0
            self.request_time = self.lamport_clock
            request_message = {"type": "request", "clock": self.lamport_clock, "peer_id": f"{self.host}:{self.port}"}
            for peer_address, peer_info in self.peer_list.items():
                if peer_address != f"{self.host}:{self.port}":
                    Utils.send_message(peer_info['host'], peer_info['port'], request_message)
            if len(self.peer_list) == 1:
                self.enter_critical_section()
        else:
            self.log("[DEBUG] Palavra já encontrada; não solicita acesso.")

    def enter_critical_section(self):
        self.in_critical_section = True
        self.requesting_critical_section = False
        if self.hash_cracker.found_word is None:
            char_count_to_process = self.get_shared_char_count()
            processing_thread = threading.Thread(
                target=self.process_task, args=(char_count_to_process,), daemon=True
            )
            processing_thread.start()
        else:
            self.exit_critical_section()

    def process_task(self, char_count):
        found = self.hash_cracker.process_combinations(char_count, self.target_hash)
        if found:
            self.log(f"[SUCCESS] Palavra encontrada: {self.hash_cracker.found_word}")
            self.exit_critical_section(found=True)
        else:
            self.exit_critical_section()

    def get_shared_char_count(self):
        if self.is_coordinator:
            char_count = self.shared_char_count
            self.shared_char_count += 1
            return char_count
        else:
            coordinator_address = None
            for peer_address, peer_info in self.peer_list.items():
                if peer_info.get("is_coordinator"):
                    coordinator_address = peer_address
                    break
            if not coordinator_address:
                self.log("[ERROR] Coordenador não encontrado.")
                return 0
            request_message = {"type": "get_char_count_request", "clock": self.lamport_clock}
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                peer_info = self.peer_list[coordinator_address]
                s.connect((peer_info['host'], peer_info['port']))
                s.sendall(json.dumps(request_message).encode('utf-8'))
                response_data = s.recv(1024).decode('utf-8')
                response = json.loads(response_data)
                s.close()
                return response['char_count']
            except Exception as e:
                self.log(f"[ERROR] Erro ao obter contador do coordenador: {e}")
                return 0

    def exit_critical_section(self, found=False):
        self.in_critical_section = False
        for peer_id in self.deferred_replies:
            reply_message = {"type": "reply", "clock": self.lamport_clock, "peer_id": f"{self.host}:{self.port}"}
            peer_info = self.peer_list[peer_id]
            Utils.send_message(peer_info['host'], peer_info['port'], reply_message)
        self.deferred_replies = []
        self.replies_received = 0
        if not found and self.hash_cracker.found_word is None:
            threading.Thread(target=self.request_access, daemon=True).start()
        elif found:
            message = {"type": "found_word", "word": self.hash_cracker.found_word, "clock": self.lamport_clock}
            for peer_address, peer_info in self.peer_list.items():
                if peer_address != f"{self.host}:{self.port}":
                    Utils.send_message(peer_info['host'], peer_info['port'], message)

class TerminalMenu:
    def __init__(self):
        self.node = None
        self.alphabet = string.ascii_letters + string.digits + string.punctuation
        self.lock = threading.Lock()

    def log_and_print(self, msg):
        with self.lock:
            print(msg)

    def run_node(self, node_instance):
        node_instance.start_server()

    def menu(self):
        while True:
            self.log_and_print("\n--- Menu Hack MD5 ---")
            self.log_and_print("1. Iniciar Coordenador")
            self.log_and_print("2. Iniciar Trabalhador")
            self.log_and_print("3. Conectar a peer")
            self.log_and_print("4. Sair")
            choice = input("Escolha uma opção: ")

            if choice == '1':
                if self.node:
                    self.log_and_print("[INFO] Já existe um nó rodando.")
                    continue
                port = input("Porta: ")
                hash_alvo = input("Hash alvo (MD5): ")
                if not port.isdigit() or not hash_alvo:
                    self.log_and_print("[ERRO] Porta deve ser número e hash não pode estar vazio.")
                    continue
                port = int(port)
                self.node = Node(port, hash_alvo, self.alphabet, is_coordinator=True)
                self.node.set_logger(self.log_and_print)
                threading.Thread(target=self.run_node, args=(self.node,), daemon=True).start()
                self.log_and_print(f"[INFO] Coordenador iniciado em {self.node.host}:{self.node.port}.")
            elif choice == '2':
                if self.node:
                    self.log_and_print("[INFO] Já existe um nó rodando.")
                    continue
                port = input("Porta: ")
                if not port.isdigit():
                    self.log_and_print("[ERRO] Porta deve ser número.")
                    continue
                port = int(port)
                self.node = Node(port, "", self.alphabet, is_coordinator=False)
                self.node.set_logger(self.log_and_print)
                threading.Thread(target=self.run_node, args=(self.node,), daemon=True).start()
                self.log_and_print(f"[INFO] Trabalhador iniciado em {self.node.host}:{self.node.port}.")
            elif choice == '3':
                if not self.node:
                    self.log_and_print("[ERRO] Inicie um nó primeiro.")
                    continue
                peer_addr = input("Endereço IP:Porta do peer: ")
                if ':' not in peer_addr:
                    self.log_and_print("[ERRO] Formato inválido. Use IP:Porta.")
                    continue
                host, port = peer_addr.split(':')
                if not port.isdigit():
                    self.log_and_print("[ERRO] Porta inválida.")
                    continue
                port = int(port)
                threading.Thread(target=self.node.connect_to_peer, args=(host, port), daemon=True).start()
                self.log_and_print("[INFO] Conectando a peer...")
            elif choice == '4':
                if self.node:
                    self.node.running = False
                    self.node.server_socket.close()
                sys.exit()

if __name__ == '__main__':
    menu = TerminalMenu()
    menu.menu()