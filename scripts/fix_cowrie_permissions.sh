#!/usr/bin/env bash
set -eu

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COWRIE_LOG_DIR="$ROOT_DIR/honeypots/logs/cowrie"

mkdir -p "$COWRIE_LOG_DIR"

if [ "$(id -u)" -ne 0 ]; then
  printf 'Esegui con sudo: sudo %s\n' "$0" >&2
  exit 1
fi

chown -R 999:999 "$COWRIE_LOG_DIR"
chmod -R u+rwX,g+rwX "$COWRIE_LOG_DIR"

printf 'Permessi Cowrie corretti: %s -> 999:999\n' "$COWRIE_LOG_DIR"
