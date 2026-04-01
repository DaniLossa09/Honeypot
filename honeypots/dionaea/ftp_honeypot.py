import socket
import threading
import json
import os
from datetime import datetime

LOG_PATH = "/var/log/dionaea/ftp.json"
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

BANNER = "220 FTP server ready\r\n"
RESPONSES = {
    "USER": "331 Password required\r\n",
    "PASS": "530 Login incorrect\r\n",
    "QUIT": "221 Goodbye\r\n",
    "SYST": "215 UNIX Type: L8\r\n",
    "FEAT": "211 No features\r\n",
    "PWD":  "257 \"/\" is current directory\r\n",
    "TYPE": "200 Type set\r\n",
    "LIST": "550 Permission denied\r\n",
    "RETR": "550 Permission denied\r\n",
    "STOR": "550 Permission denied\r\n",
}

def log(ip, port, command, argument=""):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "src_ip": ip,
        "src_port": port,
        "command": command,
        "argument": argument,
    }
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[{entry['timestamp']}] {ip}:{port} → {command} {argument}", flush=True)

def handle_client(conn, addr):
    ip, port = addr
    log(ip, port, "CONNECT")
    try:
        conn.sendall(BANNER.encode())
        while True:
            data = conn.recv(1024).decode(errors="ignore").strip()
            if not data:
                break
            parts = data.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""
            log(ip, port, cmd, arg)
            response = RESPONSES.get(cmd, "500 Unknown command\r\n")
            conn.sendall(response.encode())
            if cmd == "QUIT":
                break
    except Exception:
        pass
    finally:
        conn.close()
        log(ip, port, "DISCONNECT")

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 21))
    server.listen(50)
    print("FTP honeypot listening on port 21...", flush=True)
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()