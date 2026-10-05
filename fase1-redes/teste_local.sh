#!/usr/bin/env bash
#
# teste_local.sh — Teste funcional automático da Fase 1 (uma máquina só, Linux)
#
# Sobe servidor + sniffer + cliente no loopback, captura o tráfego e verifica,
# com asserções, que:
#   1) o servidor respondeu ao login;
#   2) o sniffer capturou pacotes do serviço alvo;
#   3) a credencial (usuario=arthur / senha=senha123) foi lida em TEXTO CLARO.
#
# Uso:   sudo ./teste_local.sh        (precisa de root por causa do socket raw)
#
set -u

PORTA=5099
BASE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
SRV_LOG="$TMP/servidor.log"
SNF_LOG="$TMP/sniffer.log"
CLI_LOG="$TMP/cliente.log"

falhou=0
checar() {  # checar "descrição" "condição já avaliada (0/1)"
    if [ "$2" -eq 0 ]; then
        echo "  [PASS] $1"
    else
        echo "  [FALHA] $1"
        falhou=1
    fi
}

echo "== Teste funcional da Fase 1 (porta $PORTA, interface lo) =="

if [ "$(id -u)" -ne 0 ]; then
    echo "AVISO: sem root, o sniffer (socket raw) não roda. Use: sudo $0"
fi

# 1) servidor
python3 "$BASE/servico_alvo/servidor.py" --host 127.0.0.1 --porta "$PORTA" >"$SRV_LOG" 2>&1 &
SRV=$!
sleep 1

# 2) sniffer (8s de captura)
timeout 8 python3 "$BASE/sniffer/sniffer.py" --porta "$PORTA" --iface lo >"$SNF_LOG" 2>&1 &
SNF=$!
sleep 1.5

# 3) cliente em modo demo
python3 "$BASE/servico_alvo/cliente.py" --host 127.0.0.1 --porta "$PORTA" --demo >"$CLI_LOG" 2>&1

sleep 1
kill "$SRV" 2>/dev/null
wait "$SNF" 2>/dev/null

# remove códigos de cor ANSI do log do sniffer para o grep
SNF_LIMPO="$TMP/sniffer_limpo.log"
sed 's/\x1b\[[0-9]*m//g' "$SNF_LOG" > "$SNF_LIMPO"

echo
echo "-- Verificações --"

grep -q "OK bem-vindo, arthur" "$CLI_LOG"; checar "servidor autenticou o login" $?
grep -q "LOGIN OK de 'arthur'"  "$SRV_LOG"; checar "servidor registrou o login no log" $?
grep -q "PAYLOAD:"              "$SNF_LIMPO"; checar "sniffer capturou payload do serviço alvo" $?
grep -q "usuario=arthur"        "$SNF_LIMPO"; checar "sniffer extraiu o USUÁRIO em claro" $?
grep -q "senha=senha123"        "$SNF_LIMPO"; checar "sniffer extraiu a SENHA em claro" $?
grep -q "cofre_saldo 15000"     "$SNF_LIMPO"; checar "sniffer leu o comando SET (valor sensível)" $?

echo
if [ "$falhou" -eq 0 ]; then
    echo ">>> RESULTADO: TODOS OS TESTES PASSARAM (Fase 1 funcional)."
else
    echo ">>> RESULTADO: HOUVE FALHAS. Veja os logs em: $TMP"
    echo "    (servidor.log, sniffer.log, cliente.log)"
fi

# Mostra o trecho da credencial capturada como prova rápida.
echo
echo "-- Prova da credencial capturada pelo sniffer --"
grep "CREDENCIAL CAPTURADA" "$SNF_LIMPO" | head -n 1 || echo "(nenhuma — verifique se rodou com sudo)"

[ "$falhou" -eq 0 ] && rm -rf "$TMP"
exit "$falhou"
