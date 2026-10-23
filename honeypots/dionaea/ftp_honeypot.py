import socket
import threading
import json
import os
import re
import uuid
import ipaddress
from datetime import datetime, timezone
from pathlib import Path

LOG_PATH = "/opt/dionaea/var/log/dionaea/ftp.json"
FAKE_ROOT = Path(os.getenv("HPX_FAKE_FTP_ROOT", "/opt/dionaea/fake_corp/ftp_root")).resolve()

MAX_COMMAND_BYTES = 8192
LOG_LOCK = threading.Lock()
DENIED_COMMANDS = {"PASV", "EPSV", "PORT", "EPRT", "LIST", "NLST", "MLSD",
                   "RETR", "STOR", "STOU", "APPE", "REST"}

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

def log(ip, port, command, argument="", *, session, username=None, local_addr):
    if not isinstance(argument, str) or len(argument) > MAX_COMMAND_BYTES + 1:
        raise ValueError('Invalid FTP argument')
    if not re.fullmatch(r'[A-Z][A-Z0-9_]{0,15}', command):
        raise ValueError('Invalid FTP event')
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": str(ipaddress.ip_address(ip)), "src_port": port,
        "dst_ip": str(ipaddress.ip_address(local_addr[0])), "dst_port": local_addr[1],
        "protocol": "ftp", "session": session,
        "command": command, "argument": argument, "username": username,
        "password": argument if command == 'PASS' else None,
    }
    with LOG_LOCK, open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    print(json.dumps(entry), flush=True)


def resolve_fake_path(cwd, argument=""):
    requested = argument.strip() or cwd
    if requested.startswith("/"):
        relative = requested.lstrip("/")
    else:
        relative = f"{cwd.strip('/')}/{requested}".strip("/")
    target = (FAKE_ROOT / relative).resolve()
    # Containment robusto: is_relative_to evita il bypass via directory "fratello"
    # (es. /ftp_root_evil) consentito dal vecchio str().startswith().
    if target != FAKE_ROOT and not target.is_relative_to(FAKE_ROOT):
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
    session = uuid.uuid4().hex
    username = None
    local_addr = conn.getsockname()
    def emit(command, argument=""):
        log(ip, port, command, argument, session=session,
            username=username, local_addr=local_addr)
    conn.settimeout(60)
    emit("CONNECT")
    try:
        conn.sendall(BANNER.encode())
        # TCP non conserva i confini dei comandi: readline gestisce sia
        # frammentazione sia piu comandi nello stesso pacchetto.
        with conn.makefile('rb') as stream:
            while True:
                line = stream.readline(MAX_COMMAND_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_COMMAND_BYTES or not line.endswith(b'\r\n'):
                    emit('INVALID', 'Command too long or missing CRLF')
                    conn.sendall(b'500 Invalid command framing\r\n')
                    break
                try:
                    data = line[:-2].decode('utf-8')
                except UnicodeDecodeError:
                    emit('INVALID', 'Invalid UTF-8 (hex prefix): ' + line[:1024].hex())
                    conn.sendall(b'501 Invalid UTF-8\r\n')
                    continue
                verb, _, arg = data.partition(' ')
                if not re.fullmatch(r'[A-Za-z]{3,16}', verb) or '\x00' in arg:
                    emit('INVALID', data)
                    conn.sendall(b'500 Invalid command\r\n')
                    continue
                cmd = verb.upper()
                if cmd == 'USER':
                    username = arg
                emit(cmd, arg)
                if cmd in DENIED_COMMANDS:
                    response = "530 Not logged in; transfers disabled\r\n"
                elif cmd == "PWD":
                    response = f'257 "{cwd}" is current directory\r\n'
                elif cmd == "CWD":
                    target = resolve_fake_path(cwd, arg)
                    if target and target.exists() and target.is_dir():
                        cwd = path_to_ftp(target)
                        response = "250 Directory changed\r\n"
                    else:
                        response = "550 Directory not found\r\n"
                else:
                    response = RESPONSES.get(cmd, "500 Unknown command\r\n")
                conn.sendall(response.encode())
                if cmd == "QUIT":
                    break
    except (OSError, TimeoutError):
        # La chiusura/timeout di una connessione non interrompe il listener.
        pass
    finally:
        conn.close()
        emit("DISCONNECT")


def main():
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
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
