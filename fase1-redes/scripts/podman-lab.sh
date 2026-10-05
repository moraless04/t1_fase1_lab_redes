#!/usr/bin/env bash
set -euo pipefail

BASE="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="localhost/fase1-redes:latest"
NET="fase1-net"
POD="fase1-cliente-observador"
SERVER="fase1-servidor"
CLIENT="fase1-cliente"
OBSERVER="fase1-observador"

usage() {
  cat <<USAGE
Uso: $0 <comando>

Comandos:
  build       constrói a imagem Podman
  up          cria a rede e sobe servidor + cliente + observador
  down        remove containers/pod/rede criados pelo laboratório
  status      mostra containers e endereços
  server      abre logs do servidor
  shell       abre shell no cliente
  observer    abre shell no observador
  sniffer     inicia o sniffer dentro do observador
  demo        executa o cliente em modo demo
USAGE
}

build() {
  podman build -t "$IMAGE" -f "$BASE/podman/Containerfile" "$BASE"
}

up() {
  podman network exists "$NET" || podman network create --subnet 10.89.0.0/24 "$NET"

  podman rm -f "$SERVER" "$CLIENT" "$OBSERVER" >/dev/null 2>&1 || true
  podman pod rm -f "$POD" >/dev/null 2>&1 || true

  podman run -d --name "$SERVER" --network "$NET" --ip 10.89.0.10 \
    "$IMAGE" python3 /app/servico_alvo/servidor.py --host 0.0.0.0 --porta 5050

  # Cliente e observador compartilham a mesma pilha de rede. Assim o
  # observador consegue capturar com AF_PACKET o tráfego gerado pelo cliente.
  podman pod create --name "$POD" --network "$NET" >/dev/null
  podman run -d --pod "$POD" --name "$CLIENT" "$IMAGE" sleep infinity
  podman run -d --pod "$POD" --name "$OBSERVER" \
    --cap-add NET_RAW --cap-add NET_ADMIN "$IMAGE" sleep infinity

  echo "Laboratório iniciado."
  status
}

down() {
  podman rm -f "$SERVER" "$CLIENT" "$OBSERVER" >/dev/null 2>&1 || true
  podman pod rm -f "$POD" >/dev/null 2>&1 || true
  podman network rm "$NET" >/dev/null 2>&1 || true
  echo "Laboratório removido."
}

status() {
  podman ps --filter name=fase1 --format 'table {{.Names}}\t{{.Status}}\t{{.Networks}}'
  echo
  podman inspect "$SERVER" --format 'servidor: {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || true
  podman inspect "$CLIENT" --format 'cliente/observador: {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || true
}

case "${1:-}" in
  build) build ;;
  up) up ;;
  down) down ;;
  status) status ;;
  server) podman logs -f "$SERVER" ;;
  shell) podman exec -it "$CLIENT" bash ;;
  observer) podman exec -it "$OBSERVER" bash ;;
  sniffer) podman exec -it "$OBSERVER" python3 /app/sniffer/sniffer.py --porta 5050 --iface eth0 ;;
  demo) podman exec -it "$CLIENT" python3 /app/servico_alvo/cliente.py --host 10.89.0.10 --porta 5050 --demo ;;
  *) usage; exit 1 ;;
esac
