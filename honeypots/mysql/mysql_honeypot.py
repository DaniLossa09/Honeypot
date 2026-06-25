#!/usr/bin/env python3
"""MySQL Honeypot — cattura tentativi di autenticazione verso servizi MySQL.

Emula un server MySQL 5.7.x: completa il handshake, cattura username
e database di destinazione, poi chiude con errore ACCESS DENIED realistico.
Log in formato JSON compatibile con il parser HoneypotX.
"""
import json
import logging
import os
import socket
import struct
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

LOG_PATH = Path(os.getenv('HPX_MYSQL_LOG', '/opt/honeypot/logs/mysql.json'))
LISTEN_HOST = os.getenv('HPX_MYSQL_HOST', '0.0.0.0')
LISTEN_PORT = int(os.getenv('HPX_MYSQL_PORT', '3306'))
SERVER_VERSION = b'5.7.43-log'

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
_log = logging.getLogger('mysql-honeypot')


def _log_event(event: dict) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open('a', encoding='utf-8') as f:
        f.write(json.dumps(event, ensure_ascii=False) + '\n')
    _log.info('event: %s', event)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _packet(payload: bytes, seq: int) -> bytes:
    length = len(payload)
    return struct.pack('<I', length)[:3] + bytes([seq]) + payload


def _handshake(conn_id: int = 1) -> bytes:
    auth_data = os.urandom(20)
    payload = (
        b'\x0a'                                    # protocol version 10
        + SERVER_VERSION + b'\x00'
        + struct.pack('<I', conn_id)               # connection id
        + auth_data[:8] + b'\x00'                 # auth-plugin-data-part-1
        + struct.pack('<H', 0xF7FF)               # capability flags lower
        + b'\x21'                                  # charset: utf8
        + struct.pack('<H', 0x0002)               # status: autocommit
        + struct.pack('<H', 0x8120)               # capability flags upper
        + bytes([21])                              # length of auth-plugin-data
        + bytes(10)                                # reserved
        + auth_data[8:] + b'\x00'                 # auth-plugin-data-part-2
        + b'mysql_native_password\x00'
    )
    return _packet(payload, seq=0)


def _error_packet(seq: int = 2) -> bytes:
    payload = (
        b'\xff'
        + struct.pack('<H', 1045)   # ER_ACCESS_DENIED_ERROR
        + b'#28000'
        + b'Access denied for user (using password: YES)'
    )
    return _packet(payload, seq=seq)


def _parse_auth_response(data: bytes) -> Tuple[Optional[str], Optional[str]]:
    try:
        if len(data) < 32:
            return None, None
        # skip: 4 cap + 4 max_pkt + 1 charset + 23 reserved = 32
        pos = 32
        end = data.index(b'\x00', pos)
        username = data[pos:end].decode('utf-8', errors='replace') or None
        pos = end + 1
        if pos >= len(data):
            return username, None
        auth_len = data[pos]
        pos += 1 + auth_len
        database = None
        if pos < len(data):
            end = data.find(b'\x00', pos)
            raw = data[pos:end] if end > pos else data[pos:]
            database = raw.decode('utf-8', errors='replace').strip('\x00') or None
        return username, database
    except Exception:
        return None, None


def _read_packet(sock: socket.socket) -> Optional[bytes]:
    try:
        hdr = b''
        while len(hdr) < 4:
            chunk = sock.recv(4 - len(hdr))
            if not chunk:
                return None
            hdr += chunk
        length = struct.unpack('<I', hdr[:3] + b'\x00')[0]
        if length > 1_000_000:
            return None
        data = b''
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    except Exception:
        return None


def _handle(conn: socket.socket, addr: tuple) -> None:
    ip, src_port = addr[0], addr[1]
    base = {
        'timestamp': _now(),
        'src_ip': ip,
        'src_port': src_port,
        'service': 'mysql',
        'dst_port': LISTEN_PORT,
    }
    try:
        conn.settimeout(10)
        _log_event({**base, 'event': 'connection'})
        conn.sendall(_handshake())

        data = _read_packet(conn)
        if not data:
            return

        username, database = _parse_auth_response(data)
        _log_event({
            **base,
            'event': 'login_attempt',
            'username': username,
            'database': database,
        })
        conn.sendall(_error_packet())

    except Exception as exc:
        _log.debug('Error from %s: %s', ip, exc)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def serve() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((LISTEN_HOST, LISTEN_PORT))
        srv.listen(128)
        _log.info('MySQL honeypot listening on %s:%d', LISTEN_HOST, LISTEN_PORT)
        while True:
            try:
                conn, addr = srv.accept()
                threading.Thread(target=_handle, args=(conn, addr), daemon=True).start()
            except Exception as exc:
                _log.error('Accept error: %s', exc)


if __name__ == '__main__':
    serve()
