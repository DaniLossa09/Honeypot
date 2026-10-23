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
import uuid
from datetime import datetime, timezone
from pathlib import Path

LOG_PATH = Path(os.getenv('HPX_SCADA_LOG', '/opt/honeypot/logs/conpot.json'))
LISTEN_HOST = os.getenv('HPX_SCADA_HOST', '0.0.0.0')
MODBUS_PORT = int(os.getenv('HPX_MODBUS_PORT', '502'))
S7_PORT = int(os.getenv('HPX_S7_PORT', '102'))

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
_log = logging.getLogger('scada-honeypot')
_LOG_LOCK = threading.Lock()
_STATE_LOCK = threading.Lock()
_MODBUS_STATE = {}
_S7_MEMORY = bytearray(4096)

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
    event = {**event, 'timestamp': _now(), 'event_id': uuid.uuid4().hex}
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _LOG_LOCK, LOG_PATH.open('a', encoding='utf-8') as f:
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
    """Memoria emulata limitata: nessun accesso a PLC o filesystem reali."""
    def invalid(code):
        return bytes([fc | 0x80, code])
    def pair(data):
        if len(data) != 4:
            raise ValueError('invalid_length')
        return struct.unpack('>HH', data)
    def check(address, count, maximum, size):
        if not 1 <= count <= maximum:
            raise ValueError('invalid_quantity')
        if address + count > size:
            raise IndexError('invalid_address')
    with _STATE_LOCK:
        registers, coils = _MODBUS_STATE.setdefault(unit_id, (_FAKE_REGISTERS[:] + [0] * 120, [True] * 2048))
        try:
            if fc in (1, 2, 3, 4):
                address, count = pair(request_data)
                bank = coils if fc in (1, 2) else registers
                check(address, count, 2000 if fc in (1, 2) else 125, len(bank))
                if fc in (1, 2):
                    packed = bytearray((count + 7) // 8)
                    for i, value in enumerate(bank[address:address + count]):
                        packed[i // 8] |= int(value) << (i % 8)
                    body = bytes(packed)
                else:
                    body = struct.pack('>' + 'H' * count, *bank[address:address + count])
                pdu = bytes([fc, len(body)]) + body
            elif fc in (5, 6):
                address, value = pair(request_data)
                bank = coils if fc == 5 else registers
                check(address, 1, 1, len(bank))
                if fc == 5 and value not in (0, 0xFF00):
                    raise ValueError('invalid_coil_value')
                bank[address] = bool(value) if fc == 5 else value
                pdu = bytes([fc]) + request_data
            elif fc in (15, 16):
                if len(request_data) < 5:
                    raise ValueError('invalid_length')
                address, count, byte_count = struct.unpack('>HHB', request_data[:5])
                bank = coils if fc == 15 else registers
                check(address, count, 1968 if fc == 15 else 123, len(bank))
                expected = (count + 7) // 8 if fc == 15 else count * 2
                if byte_count != expected or len(request_data) != 5 + expected:
                    raise ValueError('invalid_length')
                body = request_data[5:]
                values = [bool(body[i // 8] & (1 << (i % 8))) for i in range(count)] if fc == 15 else list(struct.unpack('>' + 'H' * count, body))
                bank[address:address + count] = values
                pdu = bytes([fc]) + request_data[:4]
            elif fc == 23:
                if len(request_data) < 9:
                    raise ValueError('invalid_length')
                read_address, read_count, write_address, write_count, byte_count = struct.unpack('>HHHHB', request_data[:9])
                check(read_address, read_count, 125, len(registers))
                check(write_address, write_count, 121, len(registers))
                if byte_count != write_count * 2 or len(request_data) != 9 + byte_count:
                    raise ValueError('invalid_length')
                registers[write_address:write_address + write_count] = struct.unpack('>' + 'H' * write_count, request_data[9:])
                body = struct.pack('>' + 'H' * read_count, *registers[read_address:read_address + read_count])
                pdu = bytes([fc, len(body)]) + body
            elif fc == 17 and not request_data:
                body = b'\x01\xffSiemens S7-300'
                pdu = bytes([fc, len(body)]) + body
            else:
                pdu = invalid(1)
        except ValueError:
            pdu = invalid(3)
        except IndexError:
            pdu = invalid(2)
    return struct.pack('>HHHB', transaction_id, 0, len(pdu) + 1, unit_id) + pdu


def _modbus_details(transaction_id, unit_id, fc, data):
    details = {'transaction_id': transaction_id, 'unit_id': unit_id, 'fc': fc,
               'function_code': _MODBUS_FC.get(fc, f'UNKNOWN_FC_{fc:#04x}'), 'request_hex': data.hex()}
    if len(data) >= 4:
        details['start_address'] = int.from_bytes(data[:2], 'big')
        details['value' if fc in (5, 6) else 'quantity'] = int.from_bytes(data[2:4], 'big')
    if fc in (15, 16) and len(data) >= 5 and len(data) == 5 + data[4]:
        count = int.from_bytes(data[2:4], 'big')
        if fc == 16 and data[4] == count * 2:
            details['values'] = list(struct.unpack('>' + 'H' * count, data[5:]))
        elif fc == 15 and data[4] == (count + 7) // 8:
            details['values'] = [bool(data[5 + i // 8] & (1 << (i % 8))) for i in range(count)]
    if fc == 23 and len(data) >= 9:
        details['write_address'] = int.from_bytes(data[4:6], 'big')
        details['write_quantity'] = int.from_bytes(data[6:8], 'big')
        if len(data) == 9 + data[8] and data[8] == details['write_quantity'] * 2:
            details['values'] = list(struct.unpack('>' + 'H' * details['write_quantity'], data[9:]))
    return details


def _handle_modbus(conn: socket.socket, addr: tuple) -> None:
    ip, src_port = addr[0], addr[1]
    base = {
        'session': uuid.uuid4().hex,
        'protocol': 'modbus',
        'dst_port': MODBUS_PORT,
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
            if protocol_id != 0 or length < 2 or length > 254:
                _log_event({**base, 'event': 'protocol_error', 'reason': 'invalid_mbap', 'request_hex': header.hex()})
                break

            payload = _recv_all(conn, length)
            unit_id = payload[0]
            fc = payload[1] if len(payload) > 1 else 0
            request_data = payload[2:] if len(payload) > 2 else b''

            details = _modbus_details(transaction_id, unit_id, fc, request_data)
            response = _modbus_response(transaction_id, unit_id, fc, request_data)
            details['response_hex'] = response.hex()
            if response[7] & 0x80:
                details['exception_code'] = response[8]
            _log_event({**base, 'event': 'modbus_request', 'data': details})
            conn.sendall(response)

    except Exception as exc:
        _log_event({**base, 'event': 'protocol_error', 'reason': type(exc).__name__})
    finally:
        try:
            conn.close()
        except Exception:
            pass
        _log_event({**base, 'event': 'connection_closed'})


# ── S7comm / ISO-on-TCP (porta 102) ──────────────────────────────────────────

def _tpkt(payload):
    return struct.pack('>BBH', 3, 0, len(payload) + 4) + payload


def _read_tpkt(conn):
    header = _recv_all(conn, 4)
    version, reserved, length = struct.unpack('>BBH', header)
    if version != 3 or reserved != 0 or not 7 <= length <= 8192:
        raise ValueError('invalid_tpkt')
    return _recv_all(conn, length - 4)


def _s7_ack(sequence, parameters=b'', data=b'', error=0):
    pdu = struct.pack('>BBHHHHBB', 0x32, 3, 0, sequence, len(parameters), len(data), error >> 8, error & 255)
    return _tpkt(b'\x02\xf0\x80' + pdu + parameters + data)


def _s7_job(packet, max_pdu):
    if packet[:3] != b'\x02\xf0\x80' or len(packet) < 13:
        raise ValueError('invalid_cotp_data')
    pdu = packet[3:]
    proto, kind, reserved, sequence, parameter_length, data_length = struct.unpack('>BBHHHH', pdu[:10])
    if proto != 0x32 or kind != 1 or reserved != 0 or len(pdu) != 10 + parameter_length + data_length or not parameter_length or len(pdu) > max_pdu:
        raise ValueError('invalid_s7_job')
    return sequence, pdu[10:10 + parameter_length], pdu[10 + parameter_length:]


def _s7_operation(sequence, parameters, data, max_pdu):
    function = parameters[0]
    details = {'function': _S7_FUNCTIONS.get(function, f'0x{function:02x}'),
               'request_hex': (parameters + data).hex()}
    # Una variabile DB1 di tipo byte per richiesta; le altre operazioni
    # ricevono un errore esplicito, non una falsa conferma o un timeout.
    if function not in (4, 5):
        return _s7_ack(sequence, error=0x8104), details
    if len(parameters) != 14 or parameters[1] != 1 or parameters[2:5] != b'\x12\x0a\x10':
        return _s7_ack(sequence, error=0x8500), details
    word_length = parameters[5]
    count, db_number = struct.unpack('>HH', parameters[6:10])
    area = parameters[10]
    bit_address = int.from_bytes(parameters[11:14], 'big')
    address = bit_address // 8
    details.update(db_number=db_number, area=area, word_length=word_length,
                   start_address=address, quantity=count)
    status = 0xFF
    if area != 0x84 or db_number != 1:
        status = 0x0A
    elif word_length != 2 or bit_address % 8:
        status = 0x06
    elif count < 1 or address + count > len(_S7_MEMORY) or count > max_pdu - 18:
        status = 0x05
    if function == 5:
        if len(data) != count + 4 or data[:2] != b'\x00\x04' or int.from_bytes(data[2:4], 'big') != count * 8:
            status = 0x07
        details['values_hex'] = data[4:].hex() if len(data) >= 4 else ''
    with _STATE_LOCK:
        if status == 0xFF and function == 5:
            _S7_MEMORY[address:address + count] = data[4:]
        if function == 4:
            body = struct.pack('>BBH', status, 4 if status == 0xFF else 0, count * 8 if status == 0xFF else 0)
            if status == 0xFF:
                body += bytes(_S7_MEMORY[address:address + count])
        else:
            body = bytes([status])
    details['result_code'] = status
    return _s7_ack(sequence, bytes([function, 1]), body), details


_S7_PDU_TYPES = {0x01: 'JOB', 0x02: 'ACK', 0x03: 'ACK_DATA', 0x07: 'USERDATA'}
_S7_FUNCTIONS = {0xF0: 'SETUP_COMM', 0x04: 'READ_VAR', 0x05: 'WRITE_VAR'}


def _handle_s7(conn: socket.socket, addr: tuple) -> None:
    base = {'session': uuid.uuid4().hex, 'src_ip': addr[0], 'src_port': addr[1],
            'local_port': S7_PORT, 'dst_port': S7_PORT, 'data_type': 's7comm', 'protocol': 's7comm'}
    try:
        conn.settimeout(15)
        _log_event({**base, 'event': 'connection'})
        request = _read_tpkt(conn)
        if len(request) < 7 or request[0] != len(request) - 1 or request[1] != 0xE0 or request[6] != 0:
            raise ValueError('invalid_cotp_cr')
        # Con riferimento destinazione ricavato dal client e lunghezza esatta.
        confirm = b'\x11\xd0' + request[4:6] + b'\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02'
        conn.sendall(_tpkt(confirm))
        _log_event({**base, 'event': 'handshake', 'request_hex': request.hex()})
        sequence, parameters, data = _s7_job(_read_tpkt(conn), 480)
        if len(parameters) != 8 or parameters[0] != 0xF0 or data:
            raise ValueError('setup_communication_required')
        requested = int.from_bytes(parameters[6:8], 'big')
        if requested < 64:
            raise ValueError('invalid_pdu_size')
        max_pdu = min(requested, 480)
        reply_parameters = b'\xf0\x00' + parameters[2:6] + struct.pack('>H', max_pdu)
        response = _s7_ack(sequence, reply_parameters)
        _log_event({**base, 'event': 's7_request', 'data': {'function': 'SETUP_COMM', 'request_hex': parameters.hex(), 'response_hex': response.hex()}})
        conn.sendall(response)
        while True:
            try:
                packet = _read_tpkt(conn)
            except ConnectionError:
                break
            # COTP DR (il client snap7 aggiunge un byte nullo di padding).
            if len(packet) in (7, 8) and packet[:2] == b'\x06\x80' and (len(packet) == 7 or packet[7] == 0):
                _log_event({**base, 'event': 'disconnect', 'request_hex': packet.hex()})
                try:
                    conn.sendall(_tpkt(b'\x05\xc0' + packet[4:6] + packet[2:4]))
                except OSError:
                    pass  # Il client puo avere gia chiuso dopo DR.
                break
            sequence, parameters, data = _s7_job(packet, max_pdu)
            response, details = _s7_operation(sequence, parameters, data, max_pdu)
            details['response_hex'] = response.hex()
            _log_event({**base, 'event': 's7_request', 'data': details})
            conn.sendall(response)
    except (ValueError, OSError, ConnectionError) as exc:
        _log_event({**base, 'event': 'protocol_error', 'reason': type(exc).__name__})
    finally:
        conn.close()
        _log_event({**base, 'event': 'connection_closed'})


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
