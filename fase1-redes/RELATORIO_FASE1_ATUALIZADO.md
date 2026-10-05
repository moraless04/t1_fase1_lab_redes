# Relatório — Fase 1: Reconhecimento e Escuta Passiva

**Disciplina:** Laboratório de Redes de Computadores
**Grupo:** _Arthut Ávila e Samuel Morales_
**Data:** 05/10/2026

---

## 1. Objetivo

Demonstrar, em ambiente virtual isolado, a **quebra de confidencialidade** de um
protocolo de aplicação que trafega em **texto claro**. Para isso implementamos:

1. Um **serviço alvo** (cliente + servidor) com protocolo próprio e inseguro (CVP).
2. Um **interceptador passivo** (sniffer de aplicação) que lê o tráfego usando
   **socket raw** e extrai as informações sensíveis (credenciais, mensagens, valores).

A evidência é complementada por captura no **Wireshark**, mostrando pacote a
pacote que o conteúdo trafega legível.

---

## 2. Ambiente de teste

| Papel         | Ambiente/Container              | IP              | Software executado |
|---------------|----------------------------------|-----------------|--------------------|
| Cliente       | `fase1-cliente`                  | 10.89.0.2       | `cliente.py`       |
| Servidor      | `fase1-servidor`                 | 10.89.0.10      | `servidor.py` (porta 5050) |
| Observador    | `fase1-observador` (rede do cliente) | 10.89.0.2 | `sniffer.py` + `tcpdump` |

- Rede: **`fase1-net`**, criada e gerenciada pelo Podman.
- Ambiente de validação: Linux/Codespaces com containers Podman.
- O observador utilizou `AF_PACKET`/`SOCK_RAW` para interceptar os pacotes da aplicação.
- Para gerar a captura, foi utilizado `tcpdump` dentro do container do observador.

> **Observação:** esta execução foi realizada em containers Podman para validação do projeto. O enunciado do T1 especifica uma topologia com VM-cliente, VM-servidor e VM-observador; portanto, os containers não devem ser descritos como três VMs independentes.

_(Nesta execução não foi utilizado `ip addr` de três VMs independentes.)_

---

## 3. Protocolo alvo (CVP)

Protocolo texto, orientado a linha, sobre TCP/5050. Mensagem de login:

```
LOGIN <usuario> <senha>
```

enviada **sem cifragem** — é o alvo principal da interceptação. Demais comandos:
`MSG`, `SET`, `GET`, `LIST`, `QUIT`. Credenciais e repositório chave-valor são
guardados em texto claro no servidor.

---

## 4. Execução e evidências

### 4.1. Saída do servidor (VM-servidor)

```
Na execução realizada, o serviço alvo foi iniciado pelo laboratório Podman na porta TCP 5050. A saída observável do cliente e do sniffer confirmou a comunicação e a interceptação das mensagens abaixo. A saída completa do servidor não foi registrada separadamente nesta evidência.

> `servidor: 10.89.0.10` — porta `5050` — protocolo CVP em texto claro.

### 4.2. Saída do cliente (VM-cliente)

```
<<< OK servidor CVP pronto
>>> LOGIN arthur senha123
<<< OK bem-vindo, arthur
>>> SET cofre_saldo 15000
<<< OK cofre_saldo gravado
>>> MSG A senha do deposito e deposito
<<< OK mensagem recebida: a senha do deposito e deposito
>>> GET cofre_saldo
<<< OK cofre_saldo=15000
>>> LIST
<<< OK chaves: cofre_saldo
>>> QUIT
<<< OK ate logo
```

### 4.3. Saída do sniffer passivo (VM-observador) — **evidência principal**

O interceptador, usando apenas socket raw e parsing manual de Ethernet/IP/TCP,
leu o payload da aplicação e **extraiu as credenciais em texto claro**:

```
[#1] 20:12:36 10.89.0.10:5050 -> 10.89.0.2:36742 [ACK,PSH] 23B
    PAYLOAD: 'OK servidor CVP pronto'

[#2] 20:12:36 10.89.0.2:36742 -> 10.89.0.10:5050 [ACK,PSH] 22B
    PAYLOAD: 'LOGIN arthur senha123'
>>> CREDENCIAL CAPTURADA <<< usuario=arthur  senha=senha123

[#3] 20:12:36 10.89.0.10:5050 -> 10.89.0.2:36742 [ACK,PSH] 21B
    PAYLOAD: 'OK bem-vindo, arthur'

[#4] 20:12:36 10.89.0.2:36742 -> 10.89.0.10:5050 [ACK,PSH] 22B
    PAYLOAD: 'SET cofre_saldo 15000'

[#5] 20:12:36 10.89.0.10:5050 -> 10.89.0.2:36742 [ACK,PSH] 23B
    PAYLOAD: 'OK cofre_saldo gravado'

[#6] 20:12:38 10.89.0.2:36742 -> 10.89.0.10:5050 [ACK,PSH] 35B
    PAYLOAD: 'MSG A senha do deposito e deposito'

[#7] 20:12:38 10.89.0.10:5050 -> 10.89.0.2:36742 [ACK,PSH] 53B
    PAYLOAD: 'OK mensagem recebida: a senha do deposito e deposito'

[#8] 20:12:39 10.89.0.2:36742 -> 10.89.0.10:5050 [ACK,PSH] 16B
    PAYLOAD: 'GET cofre_saldo'

[#9] 20:12:39 10.89.0.10:5050 -> 10.89.0.2:36742 [ACK,PSH] 21B
    PAYLOAD: 'OK cofre_saldo=15000'

[#10] 20:12:39 10.89.0.2:36742 -> 10.89.0.10:5050 [ACK,PSH] 5B
    PAYLOAD: 'LIST'

[#11] 20:12:39 10.89.0.10:5050 -> 10.89.0.2:36742 [ACK,PSH] 23B
    PAYLOAD: 'OK chaves: cofre_saldo'

[#12] 20:12:40 10.89.0.2:36742 -> 10.89.0.10:5050 [ACK,PSH] 5B
    PAYLOAD: 'QUIT'

[#13] 20:12:40 10.89.0.10:5050 -> 10.89.0.2:36742 [ACK,PSH] 12B
    PAYLOAD: 'OK ate logo'
```

A execução real do observador capturou **28 pacotes**, sem pacotes descartados pelo kernel. O sniffer identificou o protocolo CVP e extraiu credenciais e dados sensíveis em texto claro.

### 4.4. Evidência da captura PCAPNG

A captura foi realizada no observador com `tcpdump`, utilizando o filtro:

```text
tcp port 5050
```

Resultado da captura:

- **28 pacotes capturados**
- **0 pacotes descartados pelo kernel**
- arquivo gerado: `evidencias/fase1.pcapng`
- tamanho aproximado: **2,6 KB**

O arquivo PCAPNG deve ser aberto no Wireshark para complementar a evidência visual exigida pelo trabalho. Nesta execução, não foi gerado um print do Wireshark, portanto não são atribuídos números de pacotes do Wireshark neste relatório.

A evidência principal já obtida pelo sniffer próprio demonstra o conteúdo da aplicação em texto claro, incluindo `LOGIN arthur senha123` e `SET cofre_saldo 15000`.

---

## 5. Análise

- As credenciais (`arthur` / `senha123`) e o conteúdo da aplicação trafegaram **em texto claro** e foram lidos pelo nosso sniffer passivo, sem qualquer esforço de quebra criptográfica.
- A captura registrou comandos e respostas como `LOGIN`, `SET`, `MSG`, `GET`, `LIST` e `QUIT`, demonstrando que informações sensíveis podem ser recuperadas diretamente do payload TCP.
- Isso caracteriza **quebra de confidencialidade** para qualquer observador que consiga capturar o tráfego da aplicação.
- O interceptador utilizado é passivo: ele apenas observa e interpreta os pacotes, sem modificar o tráfego.

---

## 6. Conclusão e próximos passos

A Fase 1 comprova por que protocolos sem cifragem são inadequados para dados
sensíveis. Na **Fase 3**, o protocolo CVP será protegido com **TLS** (cifragem +
autenticação do servidor e integridade). Repetindo a mesma captura, o sniffer e
o Wireshark passarão a ver apenas **bytes cifrados** do registro TLS, sem acesso
às credenciais — fechando a vulnerabilidade demonstrada aqui.

---

## Anexos

- `servico_alvo/protocolo.py`, `servico_alvo/servidor.py`, `servico_alvo/cliente.py`
- `sniffer/sniffer.py`
- Prints dos terminais do cliente e do observador.
- `evidencias/fase1.pcapng` — captura real com 28 pacotes e 0 descartados.
- A captura pode ser aberta no Wireshark para gerar a evidência visual complementar solicitada no enunciado.
