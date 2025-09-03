import socket
import threading
import json
import time
import hashlib
import itertools
import string
import sys
import random
from contextlib import closing

# --- Constantes de Descoberta ---
COORD_DISCOVERY_PORT = 9999
COORD_DISCOVERY_MSG = "COORDINATOR_DISCOVERY"

# --- Protocolo de Comunicação (JSON Delimitado por Nova Linha) ---
def send_json_line(sock: socket.socket, message: dict):
    """Envia um objeto JSON seguido de uma nova linha."""
    try:
        data = (json.dumps(message) + "\n").encode("utf-8")
        sock.sendall(data)
    except Exception as e:
        print(f"[ERROR] Falha ao enviar dados: {e}")

def recv_json_lines(sock: socket.socket):
    """Gera objetos JSON a partir de um stream delimitado por nova linha."""
    with sock.makefile("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                print(f"[WARN] Ignorando linha JSON inválida: {line}")
                continue

class Utils:
    @staticmethod
    def send_message(target_host, target_port, message, timeout=3.0):
        """Envia uma única mensagem para um peer e fecha a conexão."""
        try:
            with closing(socket.create_connection((target_host, target_port), timeout=timeout)) as s:
                send_json_line(s, message)
            return True
        except Exception as e:
            # Silencioso para não poluir o log com nós offline
            return False

    @staticmethod
    def get_local_ip():
        """Obtém o endereço IP local."""
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
        """Testa combinações de um determinado tamanho."""
        if self.found_word is not None:
            return False
        
        self.logger(f"[INFO] Testando combinações de {char_count} caracteres...")
        for p in itertools.product(self.alphabet, repeat=char_count):
            word = "".join(p)
            word_hash = hashlib.md5(word.encode()).hexdigest()
            if word_hash == target_hash:
                self.found_word = word
                return True
        
        self.logger(f"[INFO] Nenhuma palavra encontrada com {char_count} caracteres.")
        return False

class Node:
    def __init__(self, port, target_hash, alphabet, is_coordinator=False):
        self.host = Utils.get_local_ip()
        self.port = int(port)
        self.berkley_port = random.randint(30000, 40000)
        self.peer_list = {
            f"{self.host}:{self.port}": {
                "host": self.host, "port": self.port,
                "is_coordinator": is_coordinator, "berkley_port": self.berkley_port
            }
        }
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.berkley_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.running = True
        self.is_coordinator = is_coordinator
        self.target_hash = target_hash
        self.ui_logger = print
        self.hash_cracker = HashCracker(alphabet, self.ui_logger)

        # Estado compartilhado e sincronização
        self.lock = threading.RLock()
        self.lamport_clock = 0
        self.in_critical_section = False
        self.requesting_critical_section = False
        self.is_working = False
        self.replies_received = 0
        self.replied_peers = set()
        self.deferred_replies = []
        self.request_time = 0
        
        # Gerenciamento de tarefas (Apenas Coordenador)
        self.task_counter = 1
        self.tasks_in_progress = {}

        if is_coordinator:
            self.discovery_thread = threading.Thread(target=self.discovery_responder, daemon=True)
            self.discovery_thread.start()

    def set_logger(self, logger):
        self.ui_logger = logger
        self.hash_cracker.logger = logger

    def log(self, message):
        self.ui_logger(message)

    def start_server(self):
        """Inicia os servidores TCP e UDP."""
        try:
            # Ao usar a porta 0, o SO escolhe uma porta livre.
            self.server_socket.bind((self.host, self.port))
            
            # --- LINHA ADICIONADA ---
            # Após o bind, descobrimos qual porta o SO realmente nos deu e a atualizamos.
            self.port = self.server_socket.getsockname()[1]
            
            self.server_socket.listen(20)
            # Agora o log mostrará a porta correta.
            self.log(f"[INFO] Servidor TCP ouvindo em {self.host}:{self.port}")
            
            self.berkley_socket.bind(("", self.berkley_port))
            self.log(f"[INFO] Servidor UDP Berkley ouvindo na porta {self.berkley_port}")

            threading.Thread(target=self.accept_connections, daemon=True).start()
            
            if self.is_coordinator:
                threading.Thread(target=self.berkley_coordinator, daemon=True).start()
        except Exception as e:
            self.log(f"[ERROR] Erro ao iniciar servidor: {e}")
            self.running = False

    def discovery_responder(self):
        """Responde a broadcasts de descoberta de coordenador (Apenas Coordenador)."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            try:
                sock.bind(('', COORD_DISCOVERY_PORT))
            except Exception as e:
                self.log(f"[ERROR] Erro no bind UDP discovery: {e}")
                return
            while self.running:
                try:
                    data, addr = sock.recvfrom(1024)
                    if data.decode() == COORD_DISCOVERY_MSG:
                        msg = f"{self.port}|{self.target_hash}"
                        sock.sendto(msg.encode(), addr)
                except Exception:
                    continue

    def accept_connections(self):
        """Aceita novas conexões TCP."""
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
            except Exception:
                if self.running:
                    self.log("[WARN] Erro ao aceitar conexão.")

    def handle_client(self, conn, addr):
        """Lida com mensagens de um cliente conectado."""
        with closing(conn):
            try:
                for message in recv_json_lines(conn):
                    self.update_lamport_clock(message.get('clock', 0))
                    mtype = message.get('type')

                    if mtype == 'new_peer':
                        self.handle_new_peer(conn, message)
                    elif mtype == 'peer_list_update':
                        self.update_peer_list(message['peers'])
                    elif mtype == 'request':
                        self.handle_mutex_request(message)
                    elif mtype == 'reply':
                        self.handle_mutex_reply(message)
                    elif mtype == 'found_word':
                        self.handle_found_word(message)
                    elif mtype == 'get_char_count_request' and self.is_coordinator:
                        self.handle_task_request(conn)
                    elif mtype == 'task_complete' and self.is_coordinator:
                        self.handle_task_complete(message)
            except Exception as e:
                self.log(f"[WARN] Conexão com {addr} perdida: {e}")

    def update_lamport_clock(self, received_clock=0):
        """Atualiza o relógio de Lamport de forma segura."""
        with self.lock:
            self.lamport_clock = max(self.lamport_clock, received_clock) + 1
            # self.log(f"[DEBUG] Lamport clock: {self.lamport_clock}")

    def handle_new_peer(self, conn, message):
        """Lida com um novo nó se juntando à rede."""
        if not self.is_coordinator:
            self.log("[WARN] Nó trabalhador recebeu conexão 'new_peer'. Apenas o coordenador pode adicionar nós.")
            return

        with self.lock:
            new_peer_info = {
                "host": message['host'], "port": message['port'],
                "is_coordinator": False, "berkley_port": message.get("berkley_port")
            }
            new_peer_address = f"{new_peer_info['host']}:{new_peer_info['port']}"
            if new_peer_address not in self.peer_list:
                self.peer_list[new_peer_address] = new_peer_info
                self.log(f"[INFO] Peer {new_peer_address} adicionado à lista.")
            
            # Envia a lista completa para o novo peer
            response = {"type": "peer_list_update", "peers": self.peer_list}
            send_json_line(conn, response)
            
            # Notifica os outros peers sobre a nova lista
            self.broadcast_peer_list()

    def update_peer_list(self, new_peers):
        """Atualiza a lista de peers de forma segura."""
        with self.lock:
            self.peer_list = new_peers
            self.log(f"[INFO] Lista de peers atualizada. Total: {len(self.peer_list)}")
            if not self.is_coordinator and len(self.peer_list) > 1:
                # Dispara o loop de trabalho se ainda não estiver rodando
                threading.Thread(target=self.start_worker_loop, daemon=True).start()


    def broadcast_peer_list(self):
        """Envia a lista de peers atual para todos os nós (exceto para si mesmo)."""
        with self.lock:
            message = {"type": "peer_list_update", "peers": self.peer_list}
            my_address = f"{self.host}:{self.port}"
            for addr, info in self.peer_list.items():
                if addr != my_address:
                    Utils.send_message(info['host'], info['port'], message)

    def handle_mutex_request(self, message):
        """Responde a um pedido de acesso à região crítica (Ricart-Agrawala)."""
        with self.lock:
            request_clock = message['clock']
            requesting_peer_id = message['peer_id']
            
            # Lógica de prioridade de Ricart-Agrawala
            higher_priority = (self.requesting_critical_section and 
                              ((self.request_time < request_clock) or 
                               (self.request_time == request_clock and f"{self.host}:{self.port}" < requesting_peer_id)))

            if self.in_critical_section or higher_priority:
                self.deferred_replies.append(requesting_peer_id)
                self.log(f"[MUTEX] Adiou REPLY para {requesting_peer_id}")
            else:
                peer = self.peer_list.get(requesting_peer_id)
                if peer:
                    reply = {"type": "reply", "clock": self.lamport_clock, "peer_id": f"{self.host}:{self.port}"}
                    Utils.send_message(peer['host'], peer['port'], reply)

    def handle_mutex_reply(self, message):
        """Processa uma resposta para um pedido de acesso."""
        with self.lock:
            if self.requesting_critical_section:
                self.replies_received += 1
                if self.replies_received >= len(self.peer_list) - 1:
                    self.enter_critical_section()

    def request_access(self):
        """Solicita acesso à região crítica para obter uma tarefa."""
        with self.lock:
            if self.hash_cracker.found_word: return
            self.log("[MUTEX] Solicitando acesso à região crítica para tarefa.")
            self.requesting_critical_section = True
            self.request_time = self.lamport_clock
            self.replies_received = 0
            
            if len(self.peer_list) == 1:
                self.enter_critical_section()
                return

            request_msg = {"type": "request", "clock": self.lamport_clock, "peer_id": f"{self.host}:{self.port}"}
            my_address = f"{self.host}:{self.port}"
            for addr, info in self.peer_list.items():
                if addr != my_address:
                    Utils.send_message(info['host'], info['port'], request_msg)

    def enter_critical_section(self):
        """Entra na região crítica APENAS para obter uma tarefa."""
        with self.lock:
            self.log("[MUTEX] Entrou na seção crítica.")
            self.in_critical_section = True
            self.requesting_critical_section = False
            self.is_working = True  # <-- ADICIONE ESTA LINHA (ativa a trava)

        char_count = self.get_task_from_coordinator()
        self.exit_critical_section()

        if char_count > 0 and self.hash_cracker.found_word is None:
            self.process_task(char_count)
        else:
            with self.lock:
                self.is_working = False # <-- ADICIONE ESTE BLOCO (desativa se não houver tarefa)
            self.log("[INFO] Nenhuma tarefa nova ou palavra já encontrada.")

    def exit_critical_section(self, found=False):
        """Sai da região crítica e responde a pedidos adiados."""
        with self.lock:
            self.log("[MUTEX] Saindo da seção crítica.")
            self.in_critical_section = False
            for peer_id in self.deferred_replies:
                peer = self.peer_list.get(peer_id)
                if peer:
                    reply = {"type": "reply", "clock": self.lamport_clock, "peer_id": f"{self.host}:{self.port}"}
                    Utils.send_message(peer['host'], peer['port'], reply)
            self.deferred_replies.clear()
        
        if found:
            self.broadcast_found_word()

    def process_task(self, char_count):
        """Executa a tarefa de cracking (FORA da seção crítica)."""
        found = self.hash_cracker.process_combinations(char_count, self.target_hash)

        with self.lock:
            self.is_working = False # <-- ADICIONE ESTE BLOCO (desativa a trava ao final)

        if found:
            self.log(f"[SUCCESS] Palavra encontrada: {self.hash_cracker.found_word}")
            self.broadcast_found_word()
    
    def get_task_from_coordinator(self):
        """Pede uma nova tarefa (tamanho da string) ao coordenador."""
        if self.is_coordinator:
            with self.lock:
                task_id = self.task_counter
                self.task_counter += 1
            return task_id
        
        coord_info = None
        with self.lock:
            for info in self.peer_list.values():
                if info.get("is_coordinator"):
                    coord_info = info
                    break
        if not coord_info:
            self.log("[ERROR] Coordenador não encontrado.")
            return 0

        try:
            with closing(socket.create_connection((coord_info['host'], coord_info['port']), timeout=5.0)) as s:
                self.update_lamport_clock()
                req = {"type": "get_char_count_request", "clock": self.lamport_clock}
                send_json_line(s, req)
                for resp in recv_json_lines(s):
                    return int(resp.get('char_count', 0))
        except Exception as e:
            self.log(f"[ERROR] Erro ao obter tarefa do coordenador: {e}")
            return 0
    
    def handle_task_request(self, conn):
        """Responde a um pedido de tarefa (Apenas Coordenador)."""
        with self.lock:
            if self.hash_cracker.found_word:
                task_id = 0
            else:
                task_id = self.task_counter
                self.task_counter += 1
        
        response = {"type": "char_count_reply", "char_count": task_id}
        send_json_line(conn, response)

    def notify_task_complete(self, char_count):
        """Notifica o coordenador que uma tarefa foi concluída."""
        # Implementação futura: útil para reatribuir tarefas se um nó falhar
        pass

    def handle_task_complete(self, message):
        """Processa notificação de tarefa concluída (Apenas Coordenador)."""
        pass
    
    def handle_found_word(self, message):
        """Lida com a notificação de que a palavra foi encontrada."""
        with self.lock:
            if not self.hash_cracker.found_word:
                self.hash_cracker.found_word = message['word']
                self.log(f"[SUCCESS] Palavra encontrada por outro nó: {self.hash_cracker.found_word}")

    def broadcast_found_word(self):
        """Notifica todos os outros nós que a palavra foi encontrada."""
        with self.lock:
            message = {"type": "found_word", "word": self.hash_cracker.found_word, "clock": self.lamport_clock}
            my_address = f"{self.host}:{self.port}"
            for addr, info in self.peer_list.items():
                if addr != my_address:
                    Utils.send_message(info['host'], info['port'], message)

    def connect_to_peer(self, peer_host, peer_port):
        """Conecta a um peer (coordenador) para se juntar à rede."""
        try:
            with closing(socket.create_connection((peer_host, int(peer_port)), timeout=5.0)) as s:
                self.log(f"[INFO] Conectado a {peer_host}:{peer_port}")
                self.update_lamport_clock()
                msg = {
                    "type": "new_peer", "host": self.host, "port": self.port,
                    "clock": self.lamport_clock, "berkley_port": self.berkley_port
                }
                send_json_line(s, msg)
                for response in recv_json_lines(s):
                    if response.get('type') == 'peer_list_update':
                        self.target_hash = response['peers'][f'{peer_host}:{peer_port}']['target_hash']
                        self.update_peer_list(response['peers'])
                        break
        except Exception as e:
            self.log(f"[ERROR] Erro ao conectar ao peer: {e}")
            self.running = False
    
    def berkley_coordinator(self):
        """Lógica do coordenador para o algoritmo de Berkley."""
        # A implementação de Berkley é complexa e omitida para focar na funcionalidade principal.
        # A sincronização de relógios físicos não é estritamente necessária para Ricart-Agrawala
        # funcionar, pois ele se baseia nos relógios lógicos de Lamport.
        pass

    def start_worker_loop(self):
        """Inicia o loop principal do trabalhador, que solicita tarefas continuamente."""
        self.log("[INFO] Loop de trabalho iniciado.")
        while self.running and self.hash_cracker.found_word is None:
            time.sleep(random.uniform(1, 3)) # Adiciona um pequeno atraso aleatório
            with self.lock:
                # SÓ pede uma nova tarefa se não estiver fazendo NADA.
                if not self.requesting_critical_section and not self.in_critical_section and not self.is_working:
                    self.request_access()