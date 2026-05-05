#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/honeypots/docker-compose.yml"
COWRIE_LOG_DIR="$ROOT_DIR/honeypots/logs/cowrie"
COWRIE_JSON="$COWRIE_LOG_DIR/cowrie.json"

failures=0

check() {
  local label="$1"
  shift

  if "$@" >/dev/null 2>&1; then
    printf '[OK] %s\n' "$label"
  else
    printf '[FAIL] %s\n' "$label"
    failures=$((failures + 1))
  fi
}

container_running() {
  docker ps --format '{{.Names}}' | grep -qx "$1"
}

listening_port() {
  ss -ltn "sport = :$1" | grep -q LISTEN
}

owned_by_uid_gid() {
  [ "$(stat -c '%u:%g' "$1")" = "$2" ]
}

check "docker compose file presente" test -f "$COMPOSE_FILE"
check "container cowrie presente" container_running cowrie
check "container opencanary presente" container_running opencanary
check "container FTP presente" container_running dionaea
check "porta SSH esposta sul nodo" listening_port 22
check "porta Telnet esposta sul nodo" listening_port 23
check "porta HTTP esposta sul nodo" listening_port 80
check "porta HTTPS esposta sul nodo" listening_port 443
check "porta FTP esposta sul nodo" listening_port 21
check "directory log Cowrie assegnata a uid/gid 999" owned_by_uid_gid "$COWRIE_LOG_DIR" 999:999
check "file JSON Cowrie presente" test -f "$COWRIE_JSON"
check "config Cowrie montata nel compose" grep -q 'cowrie.cfg:/cowrie/cowrie-git/etc/cowrie.cfg:ro' "$COMPOSE_FILE"
check "userdb Cowrie montato nel compose" grep -q 'userdb.txt:/cowrie/cowrie-git/etc/userdb.txt:ro' "$COMPOSE_FILE"

if [ "$failures" -eq 0 ]; then
  printf 'Healthcheck completato: nessun problema rilevato.\n'
else
  printf 'Healthcheck completato: %s problema/i rilevato/i.\n' "$failures"
fi

exit "$failures"
