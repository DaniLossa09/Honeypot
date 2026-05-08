import socket
import threading
import json
import os
from datetime import datetime
from pathlib import Path

LOG_PATH = "/opt/dionaea/var/log/dionaea/ftp.json"
FAKE_ROOT = Path(os.getenv("HPX_FAKE_FTP_ROOT", "/opt/dionaea/fake_corp/ftp_root")).resolve()
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

def resolve_fake_path(cwd, argument=""):
    requested = argument.strip() or cwd
    if requested.startswith("/"):
        relative = requested.lstrip("/")
    else:
        relative = f"{cwd.strip('/')}/{requested}".strip("/")
    target = (FAKE_ROOT / relative).resolve()
    if not str(target).startswith(str(FAKE_ROOT)):
        return None
    return target

def path_to_ftp(target):
    try:
        rel = target.relative_to(FAKE_ROOT)
    except ValueError:
        return "/"
    value = "/" + str(rel).replace(os.sep, "/")
    return "/" if value == "/." else value

def list_fake_dir(cwd, argument=""):
    target = resolve_fake_path(cwd, argument)
    if not target or not target.exists():
        return "550 Path not found\r\n"
    if target.is_file():
        size = target.stat().st_size
        return f"-rw-r--r-- 1 ftp ftp {size:>8} Jan 01 12:00 {target.name}\r\n"
    rows = []
    for item in sorted(target.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
        if item.is_dir():
            rows.append(f"drwxr-xr-x 2 ftp ftp     4096 Jan 01 12:00 {item.name}")
        else:
            rows.append(f"-rw-r--r-- 1 ftp ftp {item.stat().st_size:>8} Jan 01 12:00 {item.name}")
    return "\r\n".join(rows) + ("\r\n" if rows else "")

def retrieve_fake_file(cwd, argument=""):
    target = resolve_fake_path(cwd, argument)
    if not target or not target.exists() or not target.is_file():
        return "550 File not found\r\n"
    try:
        content = target.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return "550 Unable to read file\r\n"
    return f"150 Opening ASCII mode data connection\r\n{content}\r\n226 Transfer complete\r\n"

def handle_client(conn, addr):
    ip, port = addr
    cwd = "/"
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
            if cmd == "PWD":
                response = f"257 \"{cwd}\" is current directory\r\n"
            elif cmd == "CWD":
                target = resolve_fake_path(cwd, arg)
                if target and target.exists() and target.is_dir():
                    cwd = path_to_ftp(target)
                    response = "250 Directory changed\r\n"
                else:
                    response = "550 Directory not found\r\n"
            elif cmd == "LIST":
                response = "150 Here comes the directory listing\r\n" + list_fake_dir(cwd, arg) + "226 Directory send OK\r\n"
            elif cmd == "RETR":
                response = retrieve_fake_file(cwd, arg)
            else:
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
