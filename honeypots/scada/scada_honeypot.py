#!/usr/bin/env python3
"""SCADA Honeypot — emula PLC Siemens S7 / Modbus RTU su TCP.

Ascolta su:
  - porta 502  → Modbus/TCP (protocollo ICS più attaccato)
  - porta 102  → S7comm / ISO-on-TCP (Siemens S7-300/400/1200)

Per ogni connessione registra l'IP, il protocollo, il function code Modbus
o il tipo di PDU S7 e restituisce risposte realistiche prima di chiudere.
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

LOG_PATH = Path(os.getenv('HPX_SCADA_LOG', '/opt/honeypot/logs/conpot.json'))
LISTEN_HOST = os.getenv('HPX_SCADA_HOST', '0.0.0.0')
MODBUS_PORT = int(os.getenv('HPX_MODBUS_PORT', '502'))
S7_PORT = int(os.getenv('HPX_S7_PORT', '102'))

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
_log = logging.getLogger('scada-honeypot')

# Modbus function code -> nome (sottoinsieme più comune)
_MODBUS_FC = {
    0x01: 'READ_COILS',
    0x02: 'READ_DISCRETE_INPUTS',
    0x03: 'READ_HOLDING_REGISTERS',
    0x04: 'READ_INPUT_REGISTERS',
    0x05: 'WRITE_SINGLE_COIL',
    0x06: 'WRITE_SINGLE_REGISTER',
    0x0F: 'WRITE_MULTIPLE_COILS',
    0x10: 'WRITE_MULTIPLE_REGISTERS',
    0x11: 'REPORT_SLAVE_ID',
    0x17: 'READ_WRITE_MULTIPLE_REGISTERS',
    0x2B: 'ENCAPSULATED_INTERFACE_TRANSPORT',
}

# Valori finti dei registri holding (simulano un PLC industriale)
_FAKE_REGISTERS = [0x0064, 0x0032, 0x00C8, 0x0019, 0x03E8, 0x0000, 0x0001, 0x0002]


def _log_event(event: dict) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open('a', encoding='utf-8') as f:
        f.write(json.dumps(event, ensure_ascii=False) + '\n')
    _log.info('event: %s', event)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Modbus/TCP ────────────────────────────────────────────────────────────────

def _recv_all(sock: socket.socket, n: int) -> bytes:
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError('connection closed')
        data += chunk
    return data


def _modbus_response(transaction_id: int, unit_id: int, fc: int, request_data: bytes) -> bytes:
    """Genera una risposta Modbus realistica per i function code più comuni."""
    if fc in (0x01, 0x02):
        # Read Coils / Discrete Inputs: restituisce 1 byte con 8 coil tutte ON
        pdu = bytes([fc, 0x01, 0xFF])
    elif fc in (0x03, 0x04):
        # Read Holding/Input Registers
        count = struct.unpack('>H', request_data[2:4])[0] if len(request_data) >= 4 else 1
        count = min(count, 8)
        reg_bytes = b''.join(struct.pack('>H', _FAKE_REGISTERS[i % len(_FAKE_REGISTERS)]) for i in range(count))
        pdu = bytes([fc, count * 2]) + reg_bytes
    elif fc in (0x05, 0x06, 0x0F, 0x10):
        # Write commands: echo back address + quantity
        pdu = bytes([fc]) + request_data[:4]
    elif fc == 0x11:
        # Report Slave ID: restituisce un ID finto
        slave_data = b'\x01\xFF' + b'Siemens S7-300'
        pdu = bytes([fc, len(slave_data)]) + slave_data
    else:
        # Exception: function code non supportato
        pdu = bytes([fc | 0x80, 0x01])

    mbap = struct.pack('>HHH', transaction_id, 0, len(pdu) + 1) + bytes([unit_id])
    return mbap + pdu


def _handle_modbus(conn: socket.socket, addr: tuple) -> None:
    ip, src_port = addr[0], addr[1]
    base = {
        'timestamp': _now(),
        'src_ip': ip,
        'src_port': src_port,
        'local_port': MODBUS_PORT,
        'data_type': 'modbus',
    }
    try:
        conn.settimeout(15)
        _log_event({**base, 'event': 'connection'})

        while True:
            # MBAP header: 6 bytes
            try:
                header = _recv_all(conn, 6)
            except ConnectionError:
                break
            transaction_id, protocol_id, length = struct.unpack('>HHH', header)
            if protocol_id != 0 or length < 2 or length > 256:
                break

            payload = _recv_all(conn, length)
            unit_id = payload[0]
            fc = payload[1] if len(payload) > 1 else 0
            request_data = payload[2:] if len(payload) > 2 else b''

            fc_name = _MODBUS_FC.get(fc, f'UNKNOWN_FC_{fc:#04x}')
            data = {'function_code': fc_name, 'unit_id': unit_id}
            if len(request_data) >= 4:
                data['start_address'] = struct.unpack('>H', request_data[:2])[0]
                data['quantity'] = struct.unpack('>H', request_data[2:4])[0]

            _log_event({**base, 'event': 'modbus_request', 'data': data})
            conn.sendall(_modbus_response(transaction_id, unit_id, fc, request_data))

    except Exception as exc:
        _log.debug('Modbus error from %s: %s', ip, exc)
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ── S7comm / ISO-on-TCP (porta 102) ──────────────────────────────────────────

# COTP Connection Request response (CR)
_COTP_CC = bytes([
    0x00, 0x16,       # TPKT length
    0x03, 0x00,       # TPKT version
    0x00, 0x16,       # TPKT length (again, standard TPKT header)
    0x11,             # COTP length indicator
    0xD0,             # COTP PDU type: CC (Connection Confirm)
    0x00, 0x01,       # DST reference
    0x00, 0x01,       # SRC reference
    0x00,             # class/option
    0xC0, 0x01, 0x0A, # TPDU-size: 1024
    0xC1, 0x02, 0x01, 0x00,  # src-tsap
    0xC2, 0x02, 0x01, 0x02,  # dst-tsap (rack 0, slot 2)
])

# S7 COMM ACK_DATA per la richiesta di connessione (simplificato)
_S7_CONN_ACK = bytes([
    0x03, 0x00, 0x00, 0x1B,  # TPKT
    0x02, 0xF0, 0x80,        # COTP DT
    0x32,                    # S7 protocol ID
    0x03,                    # ACK_DATA
    0x00, 0x00,              # reserved
    0x00, 0x01,              # seq number
    0x00, 0x08,              # param length
    0x00, 0x00,              # data length
    0x00, 0x00,              # error class/code
    0xF0, 0x00,              # func: setup comm
    0x00, 0x01,              # reserved ACK queues
    0x00, 0x01,              # max AMQ calling
    0x01, 0xE0,              # max PDU length: 480
])

_S7_PDU_TYPES = {0x01: 'JOB', 0x02: 'ACK', 0x03: 'ACK_DATA', 0x07: 'USERDATA'}
_S7_FUNCTIONS = {
    0xF0: 'SETUP_COMM',
    0x04: 'READ_VAR',
    0x05: 'WRITE_VAR',
    0x1D: 'START',
    0x1E: 'STOP',
    0x28: 'DOWNLOAD_BLOCK',
    0x29: 'DOWNLOAD_ENDED',
    0x1A: 'UPLOAD_INIT',
    0x1C: 'UPLOAD_ENDED',
}


def _handle_s7(conn: socket.socket, addr: tuple) -> None:
    ip, src_port = addr[0], addr[1]
    base = {
        'timestamp': _now(),
        'src_ip': ip,
        'src_port': src_port,
        'local_port': S7_PORT,
        'data_type': 's7comm',
    }
    try:
        conn.settimeout(15)
        _log_event({**base, 'event': 'connection'})

        # Fase 1: COTP Connection Request
        data = conn.recv(1024)
        if not data:
            return

        # Risponde con COTP Connection Confirm
        conn.sendall(_COTP_CC)

        # Fase 2: S7 Setup Communication
        data = conn.recv(1024)
        if not data:
            return

        s7_info = {}
        if len(data) >= 10 and data[7:8] == b'\x32':
            pdu_type = data[8] if len(data) > 8 else 0
            func = data[17] if len(data) > 17 else 0
            s7_info = {
                'pdu_type': _S7_PDU_TYPES.get(pdu_type, f'0x{pdu_type:02x}'),
                'function': _S7_FUNCTIONS.get(func, f'0x{func:02x}'),
            }

        _log_event({**base, 'event': 's7_request', 'data': s7_info})
        conn.sendall(_S7_CONN_ACK)

        # Fase 3: ulteriori richieste
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                s7_req = {}
                if len(data) >= 18 and data[7:8] == b'\x32':
                    func = data[17] if len(data) > 17 else 0
                    s7_req['function'] = _S7_FUNCTIONS.get(func, f'0x{func:02x}')
                _log_event({**base, 'event': 's7_request', 'data': s7_req})
            except Exception:
                break

    except Exception as exc:
        _log.debug('S7 error from %s: %s', ip, exc)
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ── Server loop ───────────────────────────────────────────────────────────────

def _serve(port: int, handler, name: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((LISTEN_HOST, port))
        srv.listen(128)
        _log.info('%s honeypot listening on %s:%d', name, LISTEN_HOST, port)
        while True:
            try:
                conn, addr = srv.accept()
                threading.Thread(target=handler, args=(conn, addr), daemon=True).start()
            except Exception as exc:
                _log.error('%s accept error: %s', name, exc)


if __name__ == '__main__':
    threading.Thread(target=_serve, args=(S7_PORT, _handle_s7, 'S7comm'), daemon=True).start()
    _serve(MODBUS_PORT, _handle_modbus, 'Modbus')
