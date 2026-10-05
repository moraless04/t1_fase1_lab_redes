"""
protocolo.py — Definição do protocolo de aplicação "CVP" (Cofre de Valores em Plaintext)

Fase 1 do trabalho de Laboratório de Redes de Computadores.

Este é um protocolo PROPOSITALMENTE INSEGURO, criado pelo grupo, para demonstrar
a quebra de confidencialidade. Características inseguras (de propósito):

  - Tudo trafega em TEXTO CLARO (ASCII/UTF-8), sem cifragem.
  - Autenticação fraca: usuário e senha são enviados em claro na mesma linha.
  - Sem verificação de integridade (sem HMAC, sem hash).

O protocolo é texto, orientado a linha. Cada mensagem termina em '\n'.
A comunicação é sobre TCP, usando sockets diretamente (sem frameworks que
escondam o socket).

Gramática das mensagens (cliente -> servidor):

    LOGIN <usuario> <senha>      Autentica no servidor.
    MSG <texto livre ...>        Envia uma mensagem de chat (eco para o cliente).
    SET <chave> <valor>          Grava um valor no repositório chave-valor.
    GET <chave>                  Lê um valor do repositório.
    LIST                         Lista as chaves existentes.
    QUIT                         Encerra a sessão.

Respostas (servidor -> cliente):

    OK <texto>                   Sucesso.
    ERR <texto>                  Erro.

Porta padrão: 5050/TCP.
"""

# Porta TCP padrão do serviço alvo. O sniffer usa este mesmo valor como filtro.
PORTA_PADRAO = 5050

# Codificação de todas as mensagens.
ENCODING = "utf-8"

# Terminador de linha de cada mensagem do protocolo.
FIM_DE_LINHA = "\n"

# Base de usuários do servidor — credenciais guardadas em texto claro,
# justamente o que torna o protocolo vulnerável e interessante de atacar.
USUARIOS = {
    "arthur": "senha123",
    "admin": "tmsa@2026",
    "operador": "deposito",
}


def codificar(mensagem: str) -> bytes:
    """Converte uma mensagem de texto do protocolo em bytes prontos para o socket."""
    if not mensagem.endswith(FIM_DE_LINHA):
        mensagem += FIM_DE_LINHA
    return mensagem.encode(ENCODING)


def decodificar(dados: bytes) -> str:
    """Converte bytes recebidos do socket de volta em texto, sem o terminador."""
    return dados.decode(ENCODING, errors="replace").rstrip(FIM_DE_LINHA)
