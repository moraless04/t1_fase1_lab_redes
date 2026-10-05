# Fase 1 — Reconhecimento e Escuta Passiva

Laboratório de Redes de Computadores — serviço alvo inseguro + sniffer passivo.

Esta fase demonstra a **quebra de confidencialidade** em um protocolo de
aplicação que trafega em **texto claro**. Montamos um serviço alvo (cliente +
servidor) com um protocolo próprio e inseguro, e um interceptador passivo que lê
o tráfego diretamente da rede com **socket raw**, extraindo as credenciais.

---

## 1. O protocolo CVP (Cofre de Valores em Plaintext)

Protocolo de aplicação criado pelo grupo, **propositalmente inseguro**:

- Tudo em **texto claro** (UTF-8), orientado a linha (`\n` encerra cada mensagem).
- **Autenticação fraca**: usuário e senha enviados em claro na mesma linha.
- **Sem integridade** (sem hash/HMAC) e **sem cifragem**.
- Transporte: **TCP**, porta **5050**, usando `socket` diretamente (sem frameworks).

Comandos (cliente → servidor):

| Comando                  | Descrição                                |
|--------------------------|------------------------------------------|
| `LOGIN <usuario> <senha>`| Autentica (credenciais em texto claro).  |
| `MSG <texto>`            | Envia uma mensagem de chat.              |
| `SET <chave> <valor>`    | Grava no repositório chave-valor.        |
| `GET <chave>`            | Lê um valor.                             |
| `LIST`                   | Lista as chaves.                         |
| `QUIT`                   | Encerra a sessão.                        |

Respostas (servidor → cliente): `OK <texto>` ou `ERR <texto>`.

Usuários cadastrados para teste: `arthur/senha123`, `admin/tmsa@2026`,
`operador/deposito`.

---

## 2. Topologia do laboratório

Ambiente virtual isolado, rede **somente-host** (host-only / rede interna), sem
saída para a internet. Três VMs no mesmo segmento L2:

```
                 Rede interna isolada (ex.: 192.168.56.0/24)
                 host-only / "Internal Network"
   ┌───────────────────────┬───────────────────────┬───────────────────────┐
   │                       │                       │                       │
┌──┴──────────┐     ┌──────┴────────┐       ┌──────┴─────────┐
│ VM-CLIENTE  │     │ VM-SERVIDOR   │       │ VM-OBSERVADOR  │
│ 192.168.56.11│───▶│ 192.168.56.10 │       │ 192.168.56.12  │
│ cliente.py  │ TCP │ servidor.py   │       │ sniffer.py     │
│             │ 5050│ (porta 5050)  │       │ Wireshark      │
└─────────────┘     └───────────────┘       └────────────────┘
       │                    │                        ▲
       └────────── tráfego em texto claro ───────────┘
                    (lido passivamente)
```

- **VM-cliente** (`192.168.56.11`): executa `cliente.py`, envia credenciais e comandos.
- **VM-servidor** (`192.168.56.10`): executa `servidor.py`, atende na porta 5050.
- **VM-observador** (`192.168.56.12`): executa `sniffer.py` (socket raw) e o Wireshark.

### Observação importante sobre como o observador "enxerga" o tráfego

Em uma rede comutada (switch virtual), um host normalmente só recebe os quadros
destinados a ele. Para que a **VM-observador** veja o tráfego cliente↔servidor,
use uma das abordagens:

1. **Modo promíscuo + hub virtual**: no VirtualBox, configure as 3 VMs na mesma
   *Internal Network* e defina o *Promiscuous Mode* do adaptador da VM-observador
   como **"Allow All"**. Em redes internas do VirtualBox o encaminhamento se
   comporta como um hub, então o observador recebe os quadros.
2. **Alternativa simples (2 VMs)**: rodar o **servidor e o sniffer na mesma VM**.
   O sniffer lê o tráfego que chega à interface do servidor. Atende ao requisito
   de escuta passiva e facilita a demonstração.
3. **Port mirroring / SPAN**: se usar um switch virtual que suporte espelhamento
   de porta, espelhe a porta do servidor para a do observador.

> O sniffer é **passivo**: ele apenas lê. Não há ARP spoofing nem injeção de
> pacotes nesta fase.

---

## 3. Requisitos

- **Linux** nas VMs (o sniffer usa `AF_PACKET`, exclusivo do Linux).
- **Python 3** (biblioteca padrão apenas — nada a instalar via pip).
- O sniffer precisa de **root** (socket raw): rodar com `sudo`.
- **Wireshark** na VM-observador, para a evidência pacote a pacote.

---

## 4. Como executar

Copie a pasta `fase1-redes/` para cada Vma correspondente (ou para todas).

### 4.1. Na VM-servidor (192.168.56.10)

```bash
cd fase1-redes/servico_alvo
python3 servidor.py --host 0.0.0.0 --porta 5050
```

### 4.2. Na VM-observador (192.168.56.12) — iniciar a escuta ANTES do cliente

```bash
cd fase1-redes/sniffer
sudo python3 sniffer.py --porta 5050 --iface eth0
```

(Descubra o nome da interface com `ip link`. Omitir `--iface` escuta em todas.)

Em paralelo, abra o **Wireshark** na mesma interface com o filtro de captura
`tcp port 5050` para a evidência oficial.

### 4.3. Na VM-cliente (192.168.56.11)

Modo automático (gera um roteiro de tráfego, ideal para a captura):

```bash
cd fase1-redes/servico_alvo
python3 cliente.py --host 192.168.56.10 --porta 5050 --demo
```

Modo interativo (digitar comandos manualmente):

```bash
python3 cliente.py --host 192.168.56.10 --porta 5050
>>> LOGIN arthur senha123
>>> SET cofre_saldo 15000
>>> GET cofre_saldo
>>> QUIT
```

### 4.4. Resultado esperado no sniffer

```
[#1] 14:03:12 192.168.56.11:40312 -> 192.168.56.10:5050 [ACK,PSH] 22B
    PAYLOAD: 'LOGIN arthur senha123'
>>> CREDENCIAL CAPTURADA <<< usuario=arthur  senha=senha123
```

As credenciais aparecem **em claro**, provando a quebra de confidencialidade.

> **Nota:** se você testar tudo numa só máquina usando a interface de loopback
> (`--iface lo`), cada pacote aparece **duplicado** no sniffer. Isso é um
> comportamento normal do loopback (o quadro é visto na saída e na entrada da
> mesma interface) e **não** ocorre no laboratório com as 3 VMs, onde o
> observador vê cada quadro uma única vez.

---

## 5. Estrutura dos arquivos

```
fase1-redes/
├── README.md                  (este arquivo)
├── RELATORIO.md               (relatório com evidências)
├── servico_alvo/
│   ├── protocolo.py           (definição do protocolo e usuários)
│   ├── servidor.py            (servidor TCP, texto claro)
│   └── cliente.py             (cliente TCP, texto claro)
└── sniffer/
    └── sniffer.py             (interceptador passivo, socket raw)
```

---

## 6. Observações de segurança / escopo

- Todo o experimento roda em **ambiente virtual isolado**, sem acesso à internet.
- O sniffer só captura **a própria rede de laboratório**, para fins didáticos.
- A insegurança do protocolo é **intencional**: na Fase 3 ele será protegido
  (TLS / cifragem + autenticação), e o mesmo sniffer passará a ver apenas bytes
  cifrados.
