#!/usr/bin/env bash
# Avvia container, dashboard e backend dalla cartella del progetto.
set -euo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$PROJECT_DIR/.venv/bin/python3"
FRONTEND_PID=""
BACKEND_PID=""

fail() {
    echo "Errore: $*" >&2
    exit 1
}

cleanup() {
    local pid
    for pid in "$BACKEND_PID" "$FRONTEND_PID"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ "$EUID" -ne 0 ]] || fail "avvia lo script come utente normale, senza sudo."
[[ -x "$PYTHON" ]] || fail "Python non trovato in .venv. Crea la venv e installa requirements.txt."
command -v docker >/dev/null || fail "docker non trovato."
docker compose version >/dev/null || fail "Docker Compose non disponibile."

cd -- "$PROJECT_DIR"
echo "Avvio dei container honeypot..."
(cd honeypots && docker compose up -d --build)

echo "Avvio della dashboard sulla porta 8080..."
"$PYTHON" -u -m http.server 8080 --directory "$PROJECT_DIR/frontend" &
FRONTEND_PID=$!
sleep 1
kill -0 "$FRONTEND_PID" 2>/dev/null || fail "server dashboard non avviato; controlla che la porta 8080 sia libera."

echo "Dashboard: http://localhost:8080/dashboard_live.html"
echo "Avvio del backend con la .venv. Premi Ctrl+C per fermare backend e dashboard."
echo "I container Docker resteranno accesi."
"$PYTHON" -u run_all.py &
BACKEND_PID=$!
wait "$BACKEND_PID"
