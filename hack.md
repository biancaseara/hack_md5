---
### O Papel de Cada Método

---
#### **1. `__init__(self, host, port)`**
Este é o **construtor** da classe, que inicializa o nó com suas configurações básicas. Ele define o endereço IP (`host`) e a porta (`port`), cria a `peer_list` para armazenar informações de outros nós, e o `server_socket`, que permite a comunicação. A variável `running` serve para controlar se o nó está ativo.

---
#### **2. `start_server(self)`**
Este método coloca o nó em "modo de escuta". Ele vincula o `server_socket` ao `host` e `port` e o coloca para escutar por novas conexões. Em seguida, inicia uma nova **thread** (`accept_thread`) para gerenciar as conexões. Esse processo é fundamental, pois permite que o nó execute outras tarefas enquanto aguarda novas conexões.

---
#### **3. `accept_connections(self)`**
Essa função age como a "recepcionista" do nó. Ela fica em um **loop contínuo**, esperando que um novo nó tente se conectar. Quando uma conexão (`conn, addr`) é estabelecida, ela a delega para o método `handle_client` usando uma nova thread. Isso permite que o nó aceite várias conexões ao mesmo tempo.

---
#### **4. `handle_client(self, conn, addr)`**
Este método gerencia a **comunicação individual** com outro nó. Ele recebe e decodifica os dados enviados, como mensagens ou requisições. No futuro, essa função será responsável por interpretar essas mensagens e decidir as ações a serem tomadas, como aceitar uma requisição ou atualizar a lista de nós.

---
#### **5. `connect_to_peer(self, peer_host, peer_port)`**
Este método permite que o nó **inicie uma conexão** com outro nó já existente no sistema. Ele cria um novo socket e tenta se conectar ao `peer_host` e `peer_port`. Após a conexão, envia uma mensagem com suas próprias informações de IP e porta e, por fim, recebe a resposta do nó conectado.