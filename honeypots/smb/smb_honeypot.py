#!/usr/bin/env python3
"""SMB Honeypot — cattura tentativi di autenticazione NTLM e accesso condivisioni.

Emula un server SMB2 minimale: negozia il protocollo, invia una NTLM challenge
per stimolare le credenziali, estrae username e dominio dalla risposta AUTHENTICATE
e nega l'accesso con STATUS_ACCESS_DENIED.
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

LOG_PATH = Path(os.getenv('HPX_SMB_LOG', '/opt/honeypot/logs/smb.json'))
LISTEN_HOST = os.getenv('HPX_SMB_HOST', '0.0.0.0')
LISTEN_PORT = int(os.getenv('HPX_SMB_PORT', '445'))

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
_log = logging.getLogger('smb-honeypot')

_SMB2_MAGIC = b'\xfeSMB'
_NTLMSSP_MAGIC = b'NTLMSSP\x00'


def _log_event(event: dict) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open('a', encoding='utf-8') as f:
        f.write(json.dumps(event, ensure_ascii=False) + '\n')
    _log.info('event: %s', event)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _smb2_header(command: int, status: int = 0, msg_id: int = 0, session_id: int = 0) -> bytes:
    return (
        _SMB2_MAGIC
        + struct.pack('<H', 64)           # StructureSize
        + struct.pack('<H', 1)            # CreditCharge
        + struct.pack('<I', status)
        + struct.pack('<H', command)
        + struct.pack('<H', 1)            # Credits granted
        + struct.pack('<I', 1)            # Flags: SMB2_FLAGS_SERVER_TO_REDIR
        + struct.pack('<I', 0)            # NextCommand
        + struct.pack('<Q', msg_id)       # MessageId
        + struct.pack('<I', 0xFEFF)       # reserved / ProcessId
        + struct.pack('<I', 0)            # TreeId
        + struct.pack('<Q', session_id)
        + bytes(16)                       # Signature
    )


def _netbios_wrap(smb_msg: bytes) -> bytes:
    return struct.pack('>I', len(smb_msg)) + smb_msg


# ── SPNEGO / DER ──────────────────────────────────────────────────────────────
# I client SMB2 reali (smbclient, crackmapexec, Windows) richiedono che il
# NEGOTIATE annunci i meccanismi auth via SPNEGO e che la challenge sia
# incapsulata in un negTokenResp: senza, rifiutano con INVALID_NETWORK_RESPONSE.
_SPNEGO_OID = bytes([0x2b, 0x06, 0x01, 0x05, 0x05, 0x02])               # 1.3.6.1.5.5.2
_NTLMSSP_OID = bytes([0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a])  # 1.3.6.1.4.1.311.2.2.10


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _spnego_neg_token_init() -> bytes:
    """SPNEGO negTokenInit che annuncia il meccanismo NTLMSSP (per il NEGOTIATE)."""
    mech_types = _tlv(0x30, _tlv(0x06, _NTLMSSP_OID))      # SEQUENCE OF OID
    neg_token_init = _tlv(0x30, _tlv(0xa0, mech_types))    # NegTokenInit { mechTypes [0] }
    inner = _tlv(0x06, _SPNEGO_OID) + _tlv(0xa0, neg_token_init)
    return _tlv(0x60, inner)                               # InitialContextToken


def _spnego_neg_token_resp(ntlm: bytes) -> bytes:
    """SPNEGO negTokenResp con la challenge NTLMSSP (per il SESSION_SETUP)."""
    neg_state = _tlv(0xa0, _tlv(0x0a, b'\x01'))            # accept-incomplete
    supported_mech = _tlv(0xa1, _tlv(0x06, _NTLMSSP_OID))
    response_token = _tlv(0xa2, _tlv(0x04, ntlm))
    return _tlv(0xa1, _tlv(0x30, neg_state + supported_mech + response_token))


def _negotiate_response(msg_id: int = 0) -> bytes:
    filetime = 132000000000000000
    hdr = _smb2_header(0x0000, msg_id=msg_id)
    sec_blob = _spnego_neg_token_init()
    sec_offset = 64 + 64             # header (64) + corpo a dimensione fissa (64)
    body = (
        struct.pack('<H', 65)            # StructureSize
        + struct.pack('<H', 1)           # SecurityMode: signing enabled
        + struct.pack('<H', 0x0210)      # DialectRevision: SMB 2.1
        + struct.pack('<H', 0)           # NegotiateContextCount
        + os.urandom(16)                 # ServerGuid
        + struct.pack('<I', 0x7F)        # Capabilities
        + struct.pack('<I', 0x800000)    # MaxTransactSize
        + struct.pack('<I', 0x800000)    # MaxReadSize
        + struct.pack('<I', 0x800000)    # MaxWriteSize
        + struct.pack('<Q', filetime)    # SystemTime
        + struct.pack('<Q', filetime)    # ServerStartTime
        + struct.pack('<H', sec_offset)  # SecurityBufferOffset
        + struct.pack('<H', len(sec_blob))  # SecurityBufferLength
        + struct.pack('<I', 0)           # NegotiateContextOffset
        + sec_blob
    )
    return _netbios_wrap(hdr + body)


def _ntlm_challenge() -> bytes:
    """NTLMSSP CHALLENGE (type 2) valida: i client fanno NTLMv2 e hanno bisogno
    di un TargetInfo (AV pairs) coerente coi flag, altrimenti rifiutano l'auth."""
    server_challenge = os.urandom(8)
    target_name = 'WORKGROUP'.encode('utf-16-le')

    def _av_pair(av_id: int, value: bytes) -> bytes:
        return struct.pack('<HH', av_id, len(value)) + value

    target_info = (
        _av_pair(2, 'WORKGROUP'.encode('utf-16-le'))   # MsvAvNbDomainName
        + _av_pair(1, 'SERVER'.encode('utf-16-le'))    # MsvAvNbComputerName
        + _av_pair(0, b'')                              # MsvAvEOL
    )

    # UNICODE | REQUEST_TARGET | NTLM | TARGET_INFO (nessun VERSION → header 48 byte)
    flags = 0x00800205
    payload_off = 48
    tn_off = payload_off
    ti_off = tn_off + len(target_name)

    return (
        _NTLMSSP_MAGIC
        + struct.pack('<I', 2)                                       # MessageType CHALLENGE
        + struct.pack('<HHI', len(target_name), len(target_name), tn_off)
        + struct.pack('<I', flags)
        + server_challenge
        + bytes(8)                                                  # Reserved
        + struct.pack('<HHI', len(target_info), len(target_info), ti_off)
        + target_name
        + target_info
    )


def _session_setup_challenge(ntlm: bytes, msg_id: int = 1) -> bytes:
    STATUS_MORE = 0xC0000016
    hdr = _smb2_header(0x0001, status=STATUS_MORE, msg_id=msg_id, session_id=1)
    blob = _spnego_neg_token_resp(ntlm)   # challenge NTLMSSP incapsulata in SPNEGO
    sec_offset = 64 + 8   # from start of SMB2 message
    body = (
        struct.pack('<H', 9)              # StructureSize
        + struct.pack('<H', 0)            # SessionFlags
        + struct.pack('<H', sec_offset)   # SecurityBufferOffset
        + struct.pack('<H', len(blob))
        + blob
    )
    return _netbios_wrap(hdr + body)


def _access_denied(msg_id: int = 2) -> bytes:
    STATUS_DENIED = 0xC0000022
    hdr = _smb2_header(0x0001, status=STATUS_DENIED, msg_id=msg_id)
    body = struct.pack('<H', 9) + struct.pack('<H', 0) + struct.pack('<H', 0) + struct.pack('<H', 0)
    return _netbios_wrap(hdr + body)


def _parse_ntlm_auth(data: bytes) -> Tuple[Optional[str], Optional[str]]:
    """Estrae username e dominio dall'NTLM AUTHENTICATE (messaggio tipo 3)."""
    try:
        off = data.find(_NTLMSSP_MAGIC)
        if off < 0:
            return None, None
        msg = data[off:]
        if len(msg) < 64 or struct.unpack_from('<I', msg, 8)[0] != 3:
            return None, None

        def _field(base: int) -> Optional[str]:
            flen = struct.unpack_from('<H', msg, base)[0]
            foff = struct.unpack_from('<I', msg, base + 4)[0]
            if not flen or foff + flen > len(msg):
                return None
            return msg[foff:foff + flen].decode('utf-16-le', errors='replace').strip('\x00') or None

        return _field(36), _field(28)   # UserName, DomainName
    except Exception:
        return None, None


def _recv_netbios(sock: socket.socket) -> Optional[bytes]:
    try:
        hdr = b''
        while len(hdr) < 4:
            chunk = sock.recv(4 - len(hdr))
            if not chunk:
                return None
            hdr += chunk
        length = struct.unpack('>I', hdr)[0]
        if length > 0x400000:
            return None
        data = b''
        while len(data) < length:
            chunk = sock.recv(min(65536, length - len(data)))
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
        'service': 'smb',
        'dst_port': LISTEN_PORT,
    }
    try:
        conn.settimeout(15)
        _log_event({**base, 'event': 'connection'})

        # 1) leggi NEGOTIATE (SMB1 o SMB2)
        data = _recv_netbios(conn)
        if not data:
            return
        # alcuni client mandano prima una NetBIOS session request
        if b'\xff\x53\x4d\x42' not in data and b'\xfe\x53\x4d\x42' not in data:
            data = _recv_netbios(conn) or b''

        msg_id = 0
        if _SMB2_MAGIC in data:
            # estraiamo MessageId dalla header SMB2
            off = data.find(_SMB2_MAGIC)
            if off + 28 <= len(data):
                msg_id = struct.unpack_from('<Q', data, off + 20)[0]

        conn.sendall(_negotiate_response(msg_id=msg_id))

        # 2) SESSION_SETUP con NTLM NEGOTIATE
        data = _recv_netbios(conn)
        if not data:
            return
        next_id = msg_id + 1

        conn.sendall(_session_setup_challenge(_ntlm_challenge(), msg_id=next_id))

        # 3) SESSION_SETUP con NTLM AUTHENTICATE
        data = _recv_netbios(conn)
        if not data:
            return

        username, domain = _parse_ntlm_auth(data)
        _log_event({
            **base,
            'event': 'auth_attempt',
            'username': username,
            'domain': domain,
        })

        conn.sendall(_access_denied(msg_id=next_id + 1))

    except Exception as exc:
        _log.debug('SMB error from %s: %s', ip, exc)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def serve() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((LISTEN_HOST, LISTEN_PORT))
        srv.listen(256)
        _log.info('SMB honeypot listening on %s:%d', LISTEN_HOST, LISTEN_PORT)
        while True:
            try:
                conn, addr = srv.accept()
                threading.Thread(target=_handle, args=(conn, addr), daemon=True).start()
            except Exception as exc:
                _log.error('Accept error: %s', exc)


if __name__ == '__main__':
    serve()
