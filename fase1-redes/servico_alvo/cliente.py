#!/usr/bin/env python3
"""
cliente.py — Cliente do serviço alvo (protocolo CVP, inseguro, texto claro)

Fase 1 — Laboratório de Redes de Computadores.

Roda na VM-cliente. Usa socket TCP diretamente. Conecta no servidor e permite
digitar comandos do protocolo (LOGIN, MSG, SET, GET, LIST, QUIT).

Como tudo vai em texto claro, as credenciais digitadas no LOGIN trafegam
abertas pela rede e podem ser lidas pelo sniffer da VM-observador.

Uso:
    python3 cliente.py --host 192.168.56.10 --porta 5050

Modos:
    - Interativo (padrão): digite comandos no terminal.
    - Automático (--demo): executa uma sequência de comandos para gerar tráfego
      de demonstração (útil para capturar com o sniffer / Wireshark).
"""

import argparse
import socket
import sys
import time

import protocolo


def receber_resposta(conexao: socket.socket) -> str:
    """Lê uma resposta (uma linha) do servidor."""
    buffer = ""
    while protocolo.FIM_DE_LINHA not in buffer:
        dados = conexao.recv(4096)
        if not dados:
            break
        buffer += dados.decode(protocolo.ENCODING, errors="replace")
    return buffer.rstrip(protocolo.FIM_DE_LINHA)


def enviar(conexao: socket.socket, comando: str) -> str:
    """Envia um comando e devolve a resposta do servidor."""
    conexao.sendall(protocolo.codificar(comando))
    return receber_resposta(conexao)


def modo_demo(conexao: socket.socket) -> None:
    """Executa uma sequência fixa de comandos para gerar tráfego de captura."""
    roteiro = [
        "LOGIN arthur senha123",
        "SET cofre_saldo 15000",
        "MSG a senha do deposito e deposito",
        "GET cofre_saldo",
        "LIST",
        "QUIT",
    ]
    for comando in roteiro:
        print(f">>> {comando}")
        resposta = enviar(conexao, comando)
        print(f"<<< {resposta}")
        time.sleep(0.8)  # pausa para os pacotes ficarem separados na captura


def modo_interativo(conexao: socket.socket) -> None:
    """Lê comandos do usuário até QUIT / EOF."""
    print("Comandos: LOGIN <u> <s> | MSG <txt> | SET <k> <v> | GET <k> | LIST | QUIT")
    while True:
        try:
            comando = input(">>> ").strip()
        except EOFError:
            comando = "QUIT"
        if not comando:
            continue
        resposta = enviar(conexao, comando)
        print(f"<<< {resposta}")
        if comando.upper().startswith("QUIT"):
            break


def main() -> None:
    parser = argparse.ArgumentParser(description="Cliente do serviço alvo CVP (inseguro).")
    parser.add_argument("--host", required=True, help="IP do servidor (VM-servidor)")
    parser.add_argument("--porta", type=int, default=protocolo.PORTA_PADRAO,
                        help=f"Porta TCP (padrão: {protocolo.PORTA_PADRAO})")
    parser.add_argument("--demo", action="store_true",
                        help="Executa um roteiro automático de comandos")
    args = parser.parse_args()

    # Cria o socket TCP diretamente — sem frameworks.
    conexao = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        conexao.connect((args.host, args.porta))
    except OSError as e:
        print(f"Falha ao conectar em {args.host}:{args.porta} -> {e}")
        sys.exit(1)

    with conexao:
        # Lê o banner inicial do servidor.
        print(f"<<< {receber_resposta(conexao)}")
        if args.demo:
            modo_demo(conexao)
        else:
            modo_interativo(conexao)


if __name__ == "__main__":
    main()
