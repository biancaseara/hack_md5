import socket
import threading
import json
import time
import hashlib
import itertools
import string
import random

# Classes auxiliares
class Utils:
    def send_message(target_host, target_port, message):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_host, target_port))
            s.sendall(json.dumps(message).encode('utf-8'))
            s.close()
            return True
        except Exception as e:
            print(f"[ERROR] Não foi possível enviar a mensagem para {target_host}:{target_port}: {e}")
            return False

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
    def __init__(self, target_hash, alphabet):
        self.target_hash = target_hash
        self.alphabet = alphabet
        self.found_word = None

    def process_combinations(self, char_count):
        if self.found_word is not None:
            return False
        
        print(f"[DEBUG] Processando combinações de {char_count} caracteres...")
        
        for p in itertools.product(self.alphabet, repeat=char_count):
            word = "".join(p)
            word_hash = hashlib.md5(word.encode()).hexdigest()

            if word_hash == self.target_hash:
                self.found_word = word
                return True
            
        print(f"[DEBUG] Nenhuma palavra encontrada com {char_count} caracteres.")
        return False
    
# Classe Principal do Nó
class Node:
    def __init__(self, port, target_hash, alphabet, is_coordinator=False):
        self.host = '127.0.0.1'
        self.port = port
        self.peer_list = {f"{self.host}:{self.port}": {"host": self.host, "port": self.port, "is_coordinator": is_coordinator}}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True
        self.lamport_clock = 0
        self.is_coordinator = is_coordinator
        self.shared_char_count = 1

        self.hash_cracker = HashCracker(target_hash, alphabet)
        
        # Atributos de Ricart-Agrawala
        self.in_critical_section = False
        self.requesting_critical_section = False
        self.replies_received = 0
        self.deferred_replies = []
        self.request_time = 0

    def start_server(self):
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            print(f"[DEBUG] Servidor ouvindo em {self.host}:{self.port}")
            accept_thread = threading.Thread(target=self.accept_connections)
            accept_thread.start()

            if self.is_coordinator:
                print("[DEBUG] Nó é o coordenador do sistema.")
            
        except Exception as e:
            print(f"[ERROR] Erro ao iniciar o servidor: {e}")
            self.running = False

    def accept_connections(self):
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                print(f"[DEBUG] Conectado por {addr}")
                cliente_handler = threading.Thread(target=self.handle_client, args=(conn, addr))
                cliente_handler.start()
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[ERROR] Erro ao aceitar conexão: {e}")
                self.running = False

    def handle_client(self, conn, addr):
        try:
            data = conn.recv(1024).decode('utf-8')
            message = json.loads(data)
            received_clock = message.get('clock', 0)
            self.lamport_clock = max(self.lamport_clock, received_clock) + 1
            print(f"[DEBUG] Relógio de Lamport atualizado para: {self.lamport_clock}")

            if message['type'] == 'new_peer':
                peer_address = f"{message['host']}:{message['port']}"
                if peer_address not in self.peer_list:
                    self.peer_list[peer_address] = {"host": message['host'], "port": message['port'], "is_coordinator": message.get("is_coordinator", False)}
                    print(f"[DEBUG] Adicionado novo peer à lista: {peer_address}")
                    print(f"[DEBUG] Lista de peers atualizada: {self.peer_list}")
                response = {"type": "peer_list", "peers": self.peer_list, "clock": self.lamport_clock}
                conn.sendall(json.dumps(response).encode('utf-8'))
                
            elif message['type'] == 'peer_list':
                self.update_peer_list(message['peers'])
                self.request_access()

            elif message['type'] == 'request':
                request_clock = message['clock']
                requesting_peer_id = message['peer_id']
                higher_priority = (request_clock < self.request_time) or \
                                  (request_clock == self.request_time and requesting_peer_id < f"{self.host}:{self.port}")
                not_busy = not self.requesting_critical_section and not self.in_critical_section
                
                if not_busy or (self.requesting_critical_section and higher_priority):
                    reply_message = {"type": "reply", "clock": self.lamport_clock, "peer_id": f"{self.host}:{self.port}"}
                    Utils.send_message(self.peer_list[requesting_peer_id]['host'], self.peer_list[requesting_peer_id]['port'], reply_message)
                    print(f"[DEBUG] Enviou REPLY para {requesting_peer_id}")
                else:
                    self.deferred_replies.append(requesting_peer_id)
                    print(f"[DEBUG] Adiou REPLY para {requesting_peer_id}")

            elif message['type'] == 'reply':
                self.replies_received += 1
                print(f"[DEBUG] Resposta de REPLY recebida. Total: {self.replies_received}")
                if self.replies_received >= len(self.peer_list) - 1:
                    self.enter_critical_section()
            
            elif message['type'] == 'found_word':
                self.hash_cracker.found_word = message['word']
                print(f"[SUCCESS] Palavra encontrada por outro nó: {self.hash_cracker.found_word}")
                
            elif message['type'] == 'get_char_count_request':
                if self.is_coordinator:
                    response_message = {"type": "char_count_reply", "char_count": self.shared_char_count}
                    self.shared_char_count += 1
                    conn.sendall(json.dumps(response_message).encode('utf-8'))
            
            else:
                print(f"[DEBUG] Mensagem recebida: {message}")
        
        except Exception as e:
            print(f"[ERROR] Erro ao lidar com cliente: {e}")
        finally:
            conn.close()

    def connect_to_peer(self, peer_host, peer_port):
        try:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect((peer_host, peer_port))
            print(f"[DEBUG] Conectado a {peer_host}:{peer_port}")

            self.lamport_clock += 1
            message = {"type": "new_peer", "host": self.host, "port": self.port, "is_coordinator": self.is_coordinator, "clock": self.lamport_clock}
            peer_socket.sendall(json.dumps(message).encode('utf-8'))

            response_data = peer_socket.recv(4096).decode('utf-8')
            response = json.loads(response_data)
            
            if response['type'] == 'peer_list':
                self.update_peer_list(response['peers'])
                print(f"[DEBUG] Lista de peers recebida e atualizada. Tamanho: {len(self.peer_list)}")
                # >>> NOVO CÓDIGO AQUI
                if self.peer_list:
                    threading.Thread(target=self.request_access).start()
                # <<< NOVO CÓDIGO AQUI
        except Exception as e:
            print(f"[ERROR] Erro ao conectar a {peer_host}:{peer_port}: {e}")
        finally:
            peer_socket.close()

    def update_peer_list(self, new_peers):
        for peer_address, peer_info in new_peers.items():
            if peer_address not in self.peer_list:
                self.peer_list[peer_address] = peer_info
                print(f"[DEBUG] Adicionado novo peer à lista: {peer_address}")
        print(f"[DEBUG] Lista de peers final: {self.peer_list}")

    def request_access(self):
        if self.hash_cracker.found_word is None:
            print("[DEBUG] Solicitando acesso à região crítica...")
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
            print("[DEBUG] Palavra já encontrada. Não é necessário pedir acesso.")

    def enter_critical_section(self):
        print("[DEBUG] Entrando na região crítica...")
        self.in_critical_section = True
        self.requesting_critical_section = False
        
        if self.hash_cracker.found_word is None:
            char_count_to_process = self.get_shared_char_count()
            
            # --- CORREÇÃO AQUI ---
            processing_thread = threading.Thread(target=self.process_task, args=(char_count_to_process,))
            processing_thread.start()
            # --- FIM DA CORREÇÃO ---
        else:
            self.exit_critical_section()
    
    def process_task(self, char_count):
        found = self.hash_cracker.process_combinations(char_count)
        if found:
            print(f"[SUCCESS] Palavra encontrada: {self.hash_cracker.found_word}")
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
                print("[ERROR] Coordenador não encontrado na lista de peers.")
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
                print(f"[ERROR] Erro ao obter contador do coordenador: {e}")
                return 0

    def exit_critical_section(self, found=False):
        self.in_critical_section = False
        print("[DEBUG] Saindo da região crítica...")

        for peer_id in self.deferred_replies:
            reply_message = {"type": "reply", "clock": self.lamport_clock, "peer_id": f"{self.host}:{self.port}"}
            peer_info = self.peer_list[peer_id]
            Utils.send_message(peer_info['host'], peer_info['port'], reply_message)
        
        self.deferred_replies = []
        self.replies_received = 0
        
        if not found and self.hash_cracker.found_word is None:
            threading.Thread(target=self.request_access).start()
        elif found:
            message = {"type": "found_word", "word": self.hash_cracker.found_word, "clock": self.lamport_clock}
            for peer_address, peer_info in self.peer_list.items():
                if peer_address != f"{self.host}:{self.port}":
                    Utils.send_message(peer_info['host'], peer_info['port'], message)

if __name__ == '__main__':
    ALPHABET = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
    TARGET_HASH = "a70a73db01b6f55210b1c884c5808c67"

    node1 = Node(5000, TARGET_HASH, ALPHABET, is_coordinator=True)
    node1.start_server()
    time.sleep(2)

    pass