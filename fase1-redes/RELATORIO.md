# Relatório — Fase 1: Reconhecimento e Escuta Passiva

**Disciplina:** Laboratório de Redes de Computadores
**Grupo:** _(preencher)_
**Data:** _(preencher)_

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

| Papel         | VM            | IP (exemplo)    | Software executado         |
|---------------|---------------|-----------------|----------------------------|
| Cliente       | VM-cliente    | 192.168.56.11   | `cliente.py`               |
| Servidor      | VM-servidor   | 192.168.56.10   | `servidor.py` (porta 5050) |
| Observador    | VM-observador | 192.168.56.12   | `sniffer.py` + Wireshark   |

- Rede: **interna / host-only**, isolada, sem acesso à internet.
- SO das VMs: Linux _(ex.: Ubuntu Server 24.04)_.
- Adaptador da VM-observador em **modo promíscuo ("Allow All")**.

_(Inserir aqui um print da configuração de rede das VMs — `ip addr` de cada uma.)_

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
[14:03:10] Servidor CVP escutando em 0.0.0.0:5050 (TEXTO CLARO)
[14:03:10] Usuários cadastrados: arthur, admin, operador
[14:03:12] Conexao aberta de 192.168.56.11:40312
[14:03:12] LOGIN OK de 'arthur' (senha trafegou em claro: 'senha123')
[14:03:13] SET cofre_saldo=15000 por arthur
[14:03:14] MSG de arthur: a senha do deposito e deposito
```

_(Substituir pela saída real da sua execução + print.)_

### 4.2. Saída do cliente (VM-cliente)

```
<<< OK servidor CVP pronto
>>> LOGIN arthur senha123
<<< OK bem-vindo, arthur
>>> SET cofre_saldo 15000
<<< OK cofre_saldo gravado
>>> GET cofre_saldo
<<< OK cofre_saldo=15000
>>> QUIT
<<< OK ate logo
```

### 4.3. Saída do sniffer passivo (VM-observador) — **evidência principal**

O interceptador, usando apenas socket raw e parsing manual de Ethernet/IP/TCP,
leu o payload da aplicação e **extraiu as credenciais em texto claro**:

```
[#1] 14:03:12 192.168.56.11:40312 -> 192.168.56.10:5050 [ACK,PSH] 22B
    PAYLOAD: 'LOGIN arthur senha123'
>>> CREDENCIAL CAPTURADA <<< usuario=arthur  senha=senha123

[#2] 14:03:13 192.168.56.11:40312 -> 192.168.56.10:5050 [ACK,PSH] 20B
    PAYLOAD: 'SET cofre_saldo 15000'

[#3] 14:03:14 192.168.56.11:40312 -> 192.168.56.10:5050 [ACK,PSH] 36B
    PAYLOAD: 'MSG a senha do deposito e deposito'
```

_(Substituir pela saída real + print do terminal da VM-observador.)_

### 4.4. Evidência com Wireshark — pacote a pacote

Captura na interface da rede interna com filtro `tcp.port == 5050`.

| Nº do pacote | Origem → Destino            | Flags   | Conteúdo legível (campo *Data*)   |
|--------------|-----------------------------|---------|-----------------------------------|
| _(ex.: 4)_   | 192.168.56.11 → .10:5050     | PSH,ACK | `LOGIN arthur senha123`           |
| _(ex.: 6)_   | 192.168.56.11 → .10:5050     | PSH,ACK | `SET cofre_saldo 15000`           |
| _(ex.: 8)_   | 192.168.56.11 → .10:5050     | PSH,ACK | `MSG a senha do deposito ...`     |
| _(ex.: 10)_  | 192.168.56.10 → .11          | PSH,ACK | `OK bem-vindo, arthur`            |

> **Como obter os números dos pacotes:** no Wireshark, selecione o pacote do
> `LOGIN`, clique com o botão direito → *Follow → TCP Stream*. O número do
> pacote aparece na primeira coluna ("No."). Anote-o na tabela acima e inclua
> um print mostrando o campo de dados em ASCII com a senha visível.

_(Inserir aqui os prints do Wireshark: a lista de pacotes e o "Follow TCP Stream"
com as credenciais destacadas.)_

---

## 5. Análise

- As credenciais (`arthur` / `senha123`) e todo o conteúdo da aplicação
  trafegaram **em texto claro** e foram lidos tanto pelo nosso sniffer quanto
  pelo Wireshark, sem qualquer esforço de quebra criptográfica.
- Isso caracteriza **quebra total de confidencialidade**: qualquer host capaz de
  observar o segmento de rede obtém usuário, senha e dados sensíveis.
- O ataque é **passivo**: não houve modificação do tráfego nem interação com as
  vítimas, apenas leitura — o que o torna, na prática, indetectável pelas pontas.

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
- Prints: configuração das VMs, terminais e Wireshark.
- _(Opcional)_ arquivo `.pcapng` da captura.
