#!/usr/bin/env python3
"""
sniffer.py — Interceptador passivo (sniffer de aplicação) do protocolo CVP

Fase 1 — Laboratório de Redes de Computadores.

Roda na VM-observador. É uma ferramenta de ESCUTA PASSIVA: não envia nada na
rede, apenas lê os quadros que chegam à interface e reconstrói, camada por
camada, o conteúdo da aplicação.

A captura é feita com um SOCKET RAW próprio (não é o Wireshark, não é libpcap):

    socket.socket(AF_PACKET, SOCK_RAW, ntohs(ETH_P_ALL))

A cada quadro capturado, o programa faz o parsing manual dos cabeçalhos:

    Ethernet (14 bytes) -> IPv4 (IHL * 4 bytes) -> TCP (data offset * 4 bytes)
                                                                 |
                                                                 v
                                                      payload da aplicação

Só interessam os segmentos TCP cuja porta de origem OU destino é a porta do
serviço alvo (5050 por padrão). Desses, o payload é texto claro do protocolo
CVP — e o sniffer o exibe e destaca as credenciais do comando LOGIN.

Isto demonstra a QUEBRA DE CONFIDENCIALIDADE: sem cifragem, qualquer host que
observe o segmento de rede lê usuário e senha.

Requisitos:
    - Linux (AF_PACKET é específico do Linux).
    - Privilégio de root (socket raw): execute com sudo.

Uso:
    sudo python3 sniffer.py                       # filtra a porta 5050
    sudo python3 sniffer.py --porta 5050 --iface eth0
    sudo python3 sniffer.py --todos               # mostra todos os pacotes do alvo,
                                                   # mesmo sem payload (SYN/ACK)
"""

import argparse
import socket
import struct
import sys
from datetime import datetime

# Protocolo CVP (porta padrão). Importado da pasta do serviço se disponível;
# caso contrário, usa o valor abaixo. Mantém o sniffer independente.
PORTA_PADRAO = 5050

# Constantes de parsing.
ETH_HEADER_LEN = 14          # cabeçalho Ethernet II
ETH_TYPE_IPV4 = 0x0800       # EtherType de IPv4
IP_PROTO_TCP = 6             # número do protocolo TCP dentro do IPv4

# Cores ANSI para destacar as credenciais no terminal.
VERMELHO = "\033[91m"
AMARELO = "\033[93m"
CIANO = "\033[96m"
RESET = "\033[0m"


def mac_para_str(seis_bytes: bytes) -> str:
    """Formata 6 bytes como endereço MAC aa:bb:cc:dd:ee:ff."""
    return ":".join(f"{b:02x}" for b in seis_bytes)


def parse_ethernet(quadro: bytes):
    """Decodifica o cabeçalho Ethernet. Retorna (dst, src, ethertype, resto)."""
    dst, src, ethertype = struct.unpack("!6s6sH", quadro[:ETH_HEADER_LEN])
    return dst, src, ethertype, quadro[ETH_HEADER_LEN:]


def parse_ipv4(pacote: bytes):
    """
    Decodifica o cabeçalho IPv4. Retorna (ip_origem, ip_destino, protocolo, resto)
    ou None se não for TCP.
    """
    # Primeiro byte: versão (4 bits) + IHL (4 bits).
    primeiro = pacote[0]
    versao = primeiro >> 4
    ihl = (primeiro & 0x0F) * 4  # tamanho do cabeçalho IP em bytes

    if versao != 4:
        return None

    protocolo_l4 = pacote[9]
    ip_origem = socket.inet_ntoa(pacote[12:16])
    ip_destino = socket.inet_ntoa(pacote[16:20])

    return ip_origem, ip_destino, protocolo_l4, pacote[ihl:]


def parse_tcp(segmento: bytes):
    """
    Decodifica o cabeçalho TCP. Retorna (porta_origem, porta_destino, flags, payload).
    """
    porta_origem, porta_destino, _seq, _ack, offset_flags = struct.unpack(
        "!HHIIH", segmento[:14]
    )
    # Data offset: 4 bits altos do campo offset_flags, em palavras de 32 bits.
    data_offset = (offset_flags >> 12) * 4
    flags = offset_flags & 0x01FF
    payload = segmento[data_offset:]
    return porta_origem, porta_destino, flags, payload


def flags_para_str(flags: int) -> str:
    """Converte os bits de flag TCP em texto (SYN, ACK, PSH, FIN, RST)."""
    nomes = []
    if flags & 0x02:
        nomes.append("SYN")
    if flags & 0x10:
        nomes.append("ACK")
    if flags & 0x08:
        nomes.append("PSH")
    if flags & 0x01:
        nomes.append("FIN")
    if flags & 0x04:
        nomes.append("RST")
    return ",".join(nomes) or "-"


def destacar_credenciais(texto: str) -> str:
    """
    Procura comandos LOGIN no payload e devolve uma marcação do que foi roubado.
    Retorna string vazia se não houver credenciais na linha.
    """
    achados = []
    for linha in texto.splitlines():
        partes = linha.strip().split(" ")
        if len(partes) >= 3 and partes[0].upper() == "LOGIN":
            usuario = partes[1]
            senha = " ".join(partes[2:])
            achados.append(
                f"{VERMELHO}>>> CREDENCIAL CAPTURADA <<<{RESET} "
                f"usuario={AMARELO}{usuario}{RESET}  senha={AMARELO}{senha}{RESET}"
            )
    return "\n".join(achados)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sniffer passivo do protocolo CVP (socket raw, Linux)."
    )
    parser.add_argument("--porta", type=int, default=PORTA_PADRAO,
                        help=f"Porta do serviço alvo a filtrar (padrão: {PORTA_PADRAO})")
    parser.add_argument("--iface", default=None,
                        help="Interface de rede a escutar (ex.: eth0). Padrão: todas.")
    parser.add_argument("--todos", action="store_true",
                        help="Exibe também segmentos sem payload (SYN/ACK/FIN).")
    args = parser.parse_args()

    # Cria o socket RAW de camada 2. Captura TODOS os ethertypes (ETH_P_ALL=0x0003).
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except PermissionError:
        print("ERRO: socket raw exige root. Execute com: sudo python3 sniffer.py")
        sys.exit(1)
    except AttributeError:
        print("ERRO: AF_PACKET só existe no Linux. Rode a VM-observador em Linux.")
        sys.exit(1)

    if args.iface:
        s.bind((args.iface, 0))
        print(f"Escutando na interface {args.iface}")
    else:
        print("Escutando em TODAS as interfaces")

    print(f"Filtro: TCP porta {args.porta} (protocolo CVP, texto claro)")
    print("Aguardando tráfego... (Ctrl+C para parar)\n")

    contador = 0  # número sequencial do pacote relevante (ajuda a casar com o Wireshark)
    try:
        while True:
            quadro = s.recv(65535)

            # Camada 2 — Ethernet.
            _dst_mac, _src_mac, ethertype, resto_ip = parse_ethernet(quadro)
            if ethertype != ETH_TYPE_IPV4:
                continue

            # Camada 3 — IPv4.
            info_ip = parse_ipv4(resto_ip)
            if info_ip is None:
                continue
            ip_origem, ip_destino, proto_l4, resto_tcp = info_ip
            if proto_l4 != IP_PROTO_TCP:
                continue

            # Camada 4 — TCP.
            porta_origem, porta_destino, flags, payload = parse_tcp(resto_tcp)

            # Filtra apenas o tráfego do serviço alvo.
            if args.porta not in (porta_origem, porta_destino):
                continue

            tem_payload = len(payload) > 0
            if not tem_payload and not args.todos:
                continue

            contador += 1
            hora = datetime.now().strftime("%H:%M:%S")
            sentido = f"{ip_origem}:{porta_origem} -> {ip_destino}:{porta_destino}"
            print(f"{CIANO}[#{contador}] {hora} {sentido} "
                  f"[{flags_para_str(flags)}] {len(payload)}B{RESET}")

            if tem_payload:
                # Decodifica o payload da aplicação — texto claro do protocolo.
                texto = payload.decode("utf-8", errors="replace").rstrip("\n")
                print(f"    PAYLOAD: {texto!r}")

                # Destaca credenciais, se houver.
                roubo = destacar_credenciais(texto)
                if roubo:
                    print(roubo)
            print()

    except KeyboardInterrupt:
        print(f"\nEncerrado. {contador} pacote(s) do serviço alvo capturado(s).")
    finally:
        s.close()


if __name__ == "__main__":
    main()
