# Fase 1 — Reconhecimento e Escuta Passiva

Laboratório de Redes de Computadores — serviço alvo inseguro + sniffer passivo.

Esta fase demonstra a **quebra de confidencialidade** em um protocolo de aplicação que trafega em **texto claro**. Foi implementado um serviço alvo (cliente + servidor) com um protocolo próprio e inseguro, além de um interceptador passivo que lê o tráfego diretamente da rede com **socket raw**, extraindo informações sensíveis.

---

## 1. O protocolo CVP (Cofre de Valores em Plaintext)

O CVP é um protocolo de aplicação criado pelo grupo e **propositalmente inseguro**.

Características:

- Comunicação em **texto claro (UTF-8)**.
- Mensagens orientadas a linha (`\n` encerra cada mensagem).
- **Autenticação fraca**: usuário e senha são enviados em claro na mesma linha.
- **Sem cifragem**.
- **Sem mecanismo de integridade/autenticação forte** (sem HMAC).
- Transporte: **TCP**, porta **5050**.
- Comunicação implementada diretamente com `socket`, sem frameworks que escondam os sockets.

### Comandos cliente → servidor

| Comando | Descrição |
|---|---|
| `LOGIN <usuario> <senha>` | Autentica o usuário; credenciais trafegam em texto claro. |
| `MSG <texto>` | Envia uma mensagem de texto. |
| `SET <chave> <valor>` | Grava um valor no repositório chave-valor. |
| `GET <chave>` | Lê um valor armazenado. |
| `LIST` | Lista as chaves armazenadas. |
| `QUIT` | Encerra a sessão. |

Respostas do servidor:

```text
OK <texto>
ERR <texto>
```

Usuários cadastrados para teste:

```text
arthur / senha123
admin / tmsa@2026
operador / deposito
```

---

## 2. Topologia do laboratório

O enunciado da Fase 1 estabelece um ambiente virtual isolado com, no mínimo, três máquinas: **VM-cliente, VM-servidor e VM-observador**.

A topologia prevista para a execução conforme o enunciado é:

```text
                 Rede interna isolada
              (host-only / rede interna)

       ┌────────────────┬────────────────┬────────────────┐
       │                │                │                │
┌──────▼───────┐ ┌──────▼───────┐ ┌──────▼────────┐
│  VM-CLIENTE  │ │ VM-SERVIDOR  │ │ VM-OBSERVADOR │
│ 192.168.x.11 │ │ 192.168.x.10 │ │ 192.168.x.12  │
│              │ │              │ │               │
│ cliente.py   │ │ servidor.py  │ │ sniffer.py    │
│              │ │ TCP/5050     │ │ Wireshark     │
└──────────────┘ └──────────────┘ └───────────────┘
       │                │                ▲
       └──────── tráfego em texto claro ┘
                    (escuta passiva)
```

A interface do observador deve estar configurada de forma que permita a visualização do tráfego entre cliente e servidor, conforme a infraestrutura utilizada no laboratório.

**Importante:** a configuração acima representa a topologia exigida pelo enunciado. Durante o desenvolvimento e validação deste projeto também foi utilizado um ambiente **Podman**, descrito na seção 7. O ambiente Podman é apresentado apenas como infraestrutura de desenvolvimento/demonstração e não é descrito como três VMs independentes.

O sniffer é **passivo**: ele apenas captura e interpreta o tráfego. Não há ARP spoofing, MITM ou injeção de pacotes nesta fase.

---

## 3. Requisitos

- **Linux** para execução do sniffer, pois `AF_PACKET` é específico do Linux.
- **Python 3**.
- O sniffer utiliza apenas a biblioteca padrão do Python.
- O sniffer precisa de privilégios elevados (`sudo`) para utilizar socket raw.
- **Wireshark** deve ser utilizado na VM-observador para a evidência pacote a pacote.
- A comunicação do protocolo ocorre diretamente por sockets TCP.

---

## 4. Como executar no ambiente de três VMs

### 4.1. VM-servidor

Na VM-servidor, execute:

```bash
cd fase1-redes/servico_alvo
python3 servidor.py --host 0.0.0.0 --porta 5050
```

O servidor ficará aguardando conexões TCP na porta `5050`.

---

### 4.2. VM-observador

O sniffer deve ser iniciado **antes da execução do cliente**:

```bash
cd fase1-redes/sniffer
sudo python3 sniffer.py --porta 5050 --iface eth0
```

Caso a interface de rede possua outro nome, descubra-a com:

```bash
ip link
```

Também é possível omitir `--iface` para permitir a escuta nas interfaces disponíveis.

No Wireshark, utilize a interface correspondente e filtre o tráfego da aplicação com:

```text
tcp port 5050
```

A captura deve demonstrar, pacote a pacote, que os dados da aplicação são legíveis.

---

### 4.3. VM-cliente

Para executar a demonstração automática:

```bash
cd fase1-redes/servico_alvo
python3 cliente.py --host 192.168.56.10 --porta 5050 --demo
```

O endereço do servidor deve ser substituído pelo IP configurado na VM-servidor.

Para execução interativa:

```bash
python3 cliente.py --host 192.168.56.10 --porta 5050
```

Exemplo de comandos:

```text
>>> LOGIN arthur senha123
>>> SET cofre_saldo 15000
>>> GET cofre_saldo
>>> LIST
>>> QUIT
```

---

## 5. Resultado esperado

O sniffer passivo deve identificar o tráfego TCP da aplicação e mostrar o conteúdo do payload em texto claro.

Exemplo:

```text
[#2] 20:12:36 10.89.0.2:36742 -> 10.89.0.10:5050 [ACK,PSH] 22B
    PAYLOAD: 'LOGIN arthur senha123'

>>> CREDENCIAL CAPTURADA <<< usuario=arthur senha=senha123
```

Também devem ser observados comandos e dados como:

```text
SET cofre_saldo 15000
MSG A senha do deposito e deposito
GET cofre_saldo
LIST
QUIT
```

Isso demonstra a quebra de confidencialidade: as informações sensíveis podem ser recuperadas diretamente do tráfego, sem qualquer quebra de criptografia.

---

## 6. Estrutura dos arquivos

```text
fase1-redes/
├── README.md
├── RELATORIO.md
│
├── servico_alvo/
│   ├── protocolo.py
│   ├── servidor.py
│   └── cliente.py
│
├── sniffer/
│   └── sniffer.py
│
├── evidencias/
│   └── fase1.pcapng
│
├── podman/
│   ├── Containerfile
│   └── podman-compose.yml
│
└── scripts/
    └── podman-lab.sh
```

O arquivo `evidencias/fase1.pcapng` contém uma captura real realizada durante a validação do projeto.

---

## 7. Execução com Podman — ambiente de desenvolvimento e validação

O projeto também possui uma infraestrutura Podman para facilitar a execução em um ambiente Linux, como o GitHub Codespaces.

**Esta seção documenta o ambiente utilizado para desenvolvimento e validação do projeto. Ela não substitui a topologia de três VMs estabelecida no enunciado da Fase 1.**

### 7.1. Componentes

A infraestrutura cria os seguintes containers:

- `fase1-servidor`: servidor CVP em `10.89.0.10:5050`;
- `fase1-cliente`: cliente do protocolo;
- `fase1-observador`: sniffer passivo com `AF_PACKET`, configurado com as capacidades necessárias para captura.

### 7.2. Pré-requisito

Podman instalado e funcionando no ambiente Linux.

### 7.3. Construir e iniciar

Na raiz de `fase1-redes/`:

```bash
./scripts/podman-lab.sh build
./scripts/podman-lab.sh up
./scripts/podman-lab.sh status
```

O comando `status` deve mostrar os containers do laboratório em execução.

### 7.4. Executar o sniffer

Em um terminal:

```bash
./scripts/podman-lab.sh observer
```

O observador executa:

```bash
python3 /app/sniffer/sniffer.py --porta 5050 --iface eth0
```

### 7.5. Gerar o tráfego

Em outro terminal:

```bash
./scripts/podman-lab.sh demo
```

A demonstração gera, entre outros, os seguintes dados:

```text
LOGIN arthur senha123
SET cofre_saldo 15000
MSG A senha do deposito e deposito
GET cofre_saldo
LIST
QUIT
```

O sniffer deve mostrar esses dados em texto claro.

### 7.6. Captura PCAPNG

Durante a validação do projeto, foi realizada uma captura com `tcpdump` utilizando:

```bash
tcpdump -i eth0 -w /tmp/fase1.pcapng 'tcp port 5050'
```

A captura resultou em:

```text
28 packets captured
0 packets dropped by kernel
```

O arquivo foi copiado para:

```text
evidencias/fase1.pcapng
```

Esse arquivo pode ser aberto no Wireshark para visualizar os pacotes TCP e o conteúdo legível do protocolo CVP.

### 7.7. Acesso manual aos containers

Os scripts também permitem acessar os ambientes necessários para testes manuais:

```bash
./scripts/podman-lab.sh shell
./scripts/podman-lab.sh observer
./scripts/podman-lab.sh server
```

### 7.8. Encerrar o laboratório

```bash
./scripts/podman-lab.sh down
```

---

## 8. Evidências da Fase 1

A execução validada demonstrou que:

- o cliente estabelece uma conexão TCP com o servidor;
- o protocolo CVP trafega em texto claro;
- o sniffer próprio, implementado com socket raw, identifica os pacotes da aplicação;
- as credenciais `arthur / senha123` são recuperadas pelo sniffer;
- comandos como `SET`, `MSG`, `GET`, `LIST` e `QUIT` também são observados;
- uma captura PCAPNG foi gerada para análise no Wireshark.

Os detalhes da execução e os pacotes observados estão documentados em `RELATORIO.md`.

---

## 9. Observações de segurança e escopo

- O experimento deve ser executado somente no ambiente de laboratório autorizado.
- O sniffer é utilizado exclusivamente para capturar o tráfego da rede do experimento.
- A insegurança do protocolo é **intencional** e existe para demonstrar a quebra de confidencialidade.
- Nesta fase não há modificação do tráfego.
- A proteção do protocolo será abordada nas fases posteriores do trabalho.
