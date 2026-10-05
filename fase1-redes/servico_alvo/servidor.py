#!/usr/bin/env python3
"""
servidor.py — Servidor do serviço alvo (protocolo CVP, inseguro, texto claro)

Fase 1 — Laboratório de Redes de Computadores.

Roda na VM-servidor. Usa sockets TCP diretamente (socket.socket), sem nenhum
framework que esconda o socket. Atende múltiplos clientes com threads.

Como o protocolo trafega tudo em texto claro, o sniffer passivo da VM-observador
consegue ler credenciais, mensagens e valores apenas lendo os pacotes.

Uso:
    sudo python3 servidor.py                 # escuta em 0.0.0.0:5050
    python3 servidor.py --host 0.0.0.0 --porta 5050

(Não precisa de root; 'sudo' só é necessário se usar porta < 1024.)
"""

import argparse
import socket
import threading
from datetime import datetime

import protocolo


# Repositório chave-valor compartilhado entre todas as conexões.
# Protegido por um lock porque várias threads podem acessá-lo ao mesmo tempo.
_repositorio = {}
_repositorio_lock = threading.Lock()


def log(mensagem: str) -> None:
    """Imprime uma linha de log com horário."""
    agora = datetime.now().strftime("%H:%M:%S")
    print(f"[{agora}] {mensagem}", flush=True)


def tratar_comando(linha: str, sessao: dict) -> str:
    """
    Interpreta uma linha do protocolo e devolve a resposta (texto).

    'sessao' guarda o estado da conexão atual (ex.: se já fez login e quem é).
    """
    if not linha:
        return "ERR comando vazio"

    partes = linha.split(" ", 1)
    comando = partes[0].upper()
    argumento = partes[1] if len(partes) > 1 else ""

    if comando == "LOGIN":
        # Formato: LOGIN <usuario> <senha>
        credenciais = argumento.split(" ", 1)
        if len(credenciais) != 2:
            return "ERR uso: LOGIN <usuario> <senha>"
        usuario, senha = credenciais[0], credenciais[1]

        # Credenciais comparadas em texto claro — ponto fraco proposital.
        if protocolo.USUARIOS.get(usuario) == senha:
            sessao["usuario"] = usuario
            log(f"LOGIN OK de '{usuario}' (senha trafegou em claro: '{senha}')")
            return f"OK bem-vindo, {usuario}"
        else:
            log(f"LOGIN FALHOU para '{usuario}'")
            return "ERR credenciais invalidas"

    # A partir daqui, exige login.
    if not sessao.get("usuario"):
        return "ERR faca LOGIN primeiro"

    if comando == "MSG":
        log(f"MSG de {sessao['usuario']}: {argumento}")
        return f"OK mensagem recebida: {argumento}"

    if comando == "SET":
        kv = argumento.split(" ", 1)
        if len(kv) != 2:
            return "ERR uso: SET <chave> <valor>"
        chave, valor = kv[0], kv[1]
        with _repositorio_lock:
            _repositorio[chave] = valor
        log(f"SET {chave}={valor} por {sessao['usuario']}")
        return f"OK {chave} gravado"

    if comando == "GET":
        chave = argumento.strip()
        with _repositorio_lock:
            valor = _repositorio.get(chave)
        if valor is None:
            return f"ERR chave '{chave}' nao encontrada"
        return f"OK {chave}={valor}"

    if comando == "LIST":
        with _repositorio_lock:
            chaves = ", ".join(sorted(_repositorio)) or "(vazio)"
        return f"OK chaves: {chaves}"

    if comando == "QUIT":
        return "OK ate logo"

    return f"ERR comando desconhecido: {comando}"


def atender_cliente(conexao: socket.socket, endereco) -> None:
    """Loop de atendimento de um cliente conectado."""
    ip, porta = endereco
    log(f"Conexao aberta de {ip}:{porta}")
    sessao = {}

    # Buffer para montar linhas completas a partir dos pedaços que chegam do socket.
    buffer = ""
    try:
        with conexao:
            conexao.sendall(protocolo.codificar("OK servidor CVP pronto"))
            while True:
                dados = conexao.recv(4096)
                if not dados:
                    break  # cliente fechou a conexão
                buffer += dados.decode(protocolo.ENCODING, errors="replace")

                # Processa todas as linhas completas presentes no buffer.
                while protocolo.FIM_DE_LINHA in buffer:
                    linha, buffer = buffer.split(protocolo.FIM_DE_LINHA, 1)
                    linha = linha.strip()
                    resposta = tratar_comando(linha, sessao)
                    conexao.sendall(protocolo.codificar(resposta))
                    if linha.upper().startswith("QUIT"):
                        return
    except ConnectionError:
        pass
    finally:
        log(f"Conexao encerrada de {ip}:{porta}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Servidor do serviço alvo CVP (inseguro).")
    parser.add_argument("--host", default="0.0.0.0", help="IP de escuta (padrão: 0.0.0.0)")
    parser.add_argument("--porta", type=int, default=protocolo.PORTA_PADRAO,
                        help=f"Porta TCP (padrão: {protocolo.PORTA_PADRAO})")
    args = parser.parse_args()

    # Cria o socket TCP diretamente — sem frameworks.
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((args.host, args.porta))
    servidor.listen(5)

    log(f"Servidor CVP escutando em {args.host}:{args.porta} (TEXTO CLARO)")
    log("Usuários cadastrados: " + ", ".join(protocolo.USUARIOS))

    try:
        while True:
            conexao, endereco = servidor.accept()
            # Uma thread por cliente, para permitir o cenário com observador.
            t = threading.Thread(target=atender_cliente, args=(conexao, endereco), daemon=True)
            t.start()
    except KeyboardInterrupt:
        log("Encerrando servidor (Ctrl+C).")
    finally:
        servidor.close()


if __name__ == "__main__":
    main()
