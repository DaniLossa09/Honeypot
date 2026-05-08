#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"
COMPOSE_FILE="$ROOT_DIR/honeypots/docker-compose.yml"

if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

COWRIE_JSON="${HPX_COWRIE_LOG:-$ROOT_DIR/honeypots/logs/cowrie/cowrie.json}"
OPENCANARY_LOG="${HPX_OPENCANARY_LOG:-$ROOT_DIR/honeypots/logs/opencanary/opencanary.log}"
FTP_LOG="${HPX_FTP_LOG:-$ROOT_DIR/honeypots/logs/ftp/ftp.json}"
COWRIE_LOG_DIR="$(dirname "$COWRIE_JSON")"
API_PORT="${HPX_API_PORT:-8000}"

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
check ".env presente o default usabili" test -f "$ENV_FILE"
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
check "log OpenCanary presente" test -f "$OPENCANARY_LOG"
check "log FTP presente" test -f "$FTP_LOG"
check "porta API libera o in ascolto" sh -c "! ss -ltn 'sport = :$API_PORT' | grep -q LISTEN || true"
check "config Cowrie montata nel compose" grep -q 'cowrie.cfg:/cowrie/cowrie-git/etc/cowrie.cfg:ro' "$COMPOSE_FILE"
check "userdb Cowrie montato nel compose" grep -q 'userdb.txt:/cowrie/cowrie-git/etc/userdb.txt:ro' "$COMPOSE_FILE"

if [ "$failures" -eq 0 ]; then
  printf 'Healthcheck completato: nessun problema rilevato.\n'
else
  printf 'Healthcheck completato: %s problema/i rilevato/i.\n' "$failures"
fi

exit "$failures"
