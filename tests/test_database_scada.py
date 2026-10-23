"""Regressioni per i responder e lo schema; nessuna scrittura nei log operativi."""
import importlib.util
import json
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch


def load_service(name):
    root = Path(__file__).resolve().parents[1]
    path = root / 'honeypots' / name / (name + '_honeypot.py')
    spec = importlib.util.spec_from_file_location('test_' + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ModbusResponderTest(unittest.TestCase):
    def setUp(self):
        self.service = load_service('scada')

    def request(self, fc, data):
        reply = self.service._modbus_response(321, 1, fc, data)
        self.assertEqual(struct.unpack('>HHH', reply[:6]), (321, 0, len(reply) - 6))
        return reply[7:]

    def read(self, address, count):
        pdu = self.request(3, struct.pack('>HH', address, count))
        return list(struct.unpack('>' + 'H' * count, pdu[2:]))

    def test_addresses_quantities_and_single_write_are_coherent(self):
        self.assertEqual(self.read(3, 1), [25])
        self.assertEqual(len(self.read(0, 10)), 10)
        self.assertEqual(self.request(6, struct.pack('>HH', 0, 321)), b'\x06\x00\x00\x01A')
        self.assertEqual(self.read(0, 1), [321])

    def test_multiple_writes_and_readwrite_are_coherent(self):
        self.request(16, struct.pack('>HHBHH', 2, 2, 4, 11, 22))
        self.assertEqual(self.read(2, 2), [11, 22])
        reply = self.request(23, struct.pack('>HHHHBHH', 0, 2, 0, 2, 4, 44, 55))
        self.assertEqual(reply, b'\x17\x04\x00,\x007')
        self.assertEqual(self.read(0, 2), [44, 55])

    def test_coils_have_correct_length_and_preserve_writes(self):
        self.assertEqual(len(self.request(1, struct.pack('>HH', 0, 16))[2:]), 2)
        self.request(5, struct.pack('>HH', 0, 0))
        self.assertEqual(self.request(1, struct.pack('>HH', 0, 1)), b'\x01\x01\x00')
        self.request(15, struct.pack('>HHB', 0, 3, 1) + b'\x05')
        self.assertEqual(self.request(1, struct.pack('>HH', 0, 3)), b'\x01\x01\x05')

    def test_invalid_lengths_quantities_and_addresses_get_exceptions(self):
        for data, code in [(b'\x00', 3), (struct.pack('>HH', 0, 0), 3),
                           (struct.pack('>HH', 0, 126), 3), (struct.pack('>HH', 127, 2), 2)]:
            self.assertEqual(self.request(3, data), bytes([0x83, code]))
        before = self.read(0, 1)
        self.assertEqual(self.request(16, struct.pack('>HHB', 0, 2, 1) + b'\x01'), b'\x90\x03')
        self.assertEqual(self.read(0, 1), before)

    def test_log_preserves_write_values(self):
        details = self.service._modbus_details(1, 1, 6, struct.pack('>HH', 0, 321))
        self.assertEqual(details['value'], 321)
        self.assertNotIn('quantity', details)
        details = self.service._modbus_details(1, 1, 16, struct.pack('>HHBHH', 2, 2, 4, 11, 22))
        self.assertEqual(details['values'], [11, 22])


class SourceIdentityTest(unittest.TestCase):
    def test_repeated_events_stay_distinct_even_if_clock_does_not_advance(self):
        for source in ('mysql', 'scada'):
            service = load_service(source)
            with tempfile.TemporaryDirectory() as td:
                service.LOG_PATH = Path(td) / 'log.json'
                with patch.object(service, '_now', return_value='2026-10-20T00:00:00+00:00'):
                    service._log_event({'event': 'connection'})
                    service._log_event({'event': 'connection'})
                rows = [json.loads(line) for line in service.LOG_PATH.read_text().splitlines()]
                self.assertEqual(len(rows), 2)
                self.assertNotEqual(rows[0]['event_id'], rows[1]['event_id'])


class MysqlAuthenticationTest(unittest.TestCase):
    def setUp(self):
        self.service = load_service('mysql')

    def test_database_and_plugin_are_not_confused(self):
        flags = 0x0200 | 0x8000 | 0x80000
        header = struct.pack('<I', flags) + bytes(28)
        self.assertEqual(self.service._parse_auth_response(header + b'audit\x00\x00mysql_native_password\x00'), ('audit', None))
        header = struct.pack('<I', flags | 8) + bytes(28)
        self.assertEqual(self.service._parse_auth_response(header + b'audit\x00\x00db1\x00mysql_native_password\x00'), ('audit', 'db1'))

    def test_truncated_auth_is_rejected(self):
        for payload in [b'', bytes(32), struct.pack('<I', 0x8200) + bytes(28) + b'audit\x00\x10x']:
            with self.assertRaises(ValueError):
                self.service._parse_auth_response(payload)


class ProtocolSchemaTest(unittest.TestCase):
    def test_scada_fields_and_metadata_classification(self):
        from backend.parsers import parse_scada_line
        from backend.classifier import classify_attack
        base = {'timestamp': '2026-10-20T00:00:00Z', 'src_ip': '::1', 'src_port': 50000,
                'local_port': 102, 'data_type': 's7comm', 'event': 's7_request'}
        for function in ['READ_VAR', 'WRITE_VAR']:
            record = parse_scada_line(json.dumps({**base, 'data': {'function': function}}))
            self.assertEqual((record['port'], record['src_port'], record['dst_port']), (102, 50000, 102))
            self.assertEqual(record['command'], function)
            self.assertEqual(record['eventid'], 's7_request')
            self.assertEqual(classify_attack(record), 'SCADA Attack')
        for obj in [{**base, 'event': 'connection'}, {**base, 'data': {'function': 'SETUP_COMM'}}]:
            self.assertIsNone(classify_attack(parse_scada_line(json.dumps(obj))))

    def test_bad_schema_is_rejected_at_each_boundary(self):
        from backend.parsers import parse_mysql_line, parse_scada_line
        from backend.classifier import classify_attack
        from backend.db import insert_raw_event
        mysql = {'timestamp': '2026-10-20T00:00:00Z', 'src_ip': '127.0.0.1',
                 'event': 'login_attempt', 'username': 'audit', 'dst_port': 3306}
        scada = {**mysql, 'event': 'modbus_request', 'data_type': 'modbus',
                 'data': {'function_code': 'READ_COILS', 'quantity': 16}}
        for parser, base in [(parse_mysql_line, mysql), (parse_scada_line, scada)]:
            for change in [{'src_ip': 'invalid'}, {'src_port': True}, {'timestamp': []}]:
                with self.assertRaises(ValueError):
                    parser(json.dumps({**base, **change}))
            record = parser(json.dumps(base))
            record['raw_event']['event'] = []
            for boundary in (classify_attack, insert_raw_event):
                with self.assertRaises(ValueError):
                    boundary(record)
        with self.assertRaises(ValueError):
            parse_scada_line(json.dumps({**scada, 'data': {'values': [{}]}}))

    def test_mysql_port_and_metadata(self):
        from backend.parsers import parse_mysql_line
        from backend.classifier import classify_attack, classify_signal
        obj = {'timestamp': '2026-10-20T00:00:00Z', 'src_ip': '127.0.0.1',
               'src_port': 50000, 'dst_port': 3306, 'event': 'handshake'}
        record = parse_mysql_line(json.dumps(obj))
        self.assertEqual((record['port'], record['src_port'], record['dst_port']), (3306, 50000, 3306))
        self.assertIsNone(record['command'])
        self.assertIsNone(classify_attack(record))
        self.assertIsNone(classify_signal(record))


class S7TcpTest(unittest.TestCase):
    def setUp(self):
        self.service = load_service('scada')
        self.tmp = tempfile.TemporaryDirectory()
        self.service.LOG_PATH = Path(self.tmp.name) / 's7.json'
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.listener.settimeout(3)
        self.service.S7_PORT = self.listener.getsockname()[1]
        def serve():
            conn, addr = self.listener.accept()
            self.service._handle_s7(conn, addr)
        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()
        self.client = socket.create_connection(self.listener.getsockname(), timeout=3)
        self.client.settimeout(3)

    def tearDown(self):
        self.client.close()
        self.thread.join(3)
        self.listener.close()
        self.tmp.cleanup()

    def packet(self, pdu):
        body = b'\x02\xf0\x80' + pdu
        return struct.pack('>BBH', 3, 0, len(body) + 4) + body

    def receive(self):
        def read(n):
            data = b''
            while len(data) < n:
                part = self.client.recv(n - len(data))
                self.assertTrue(part)
                data += part
            return data
        header = read(4)
        self.assertEqual(header[:2], b'\x03\x00')
        return read(int.from_bytes(header[2:4], 'big') - 4)

    def job(self, sequence, params, data=b''):
        return self.packet(struct.pack('>BBHHHH', 0x32, 1, 0, sequence, len(params), len(data)) + params + data)

    def test_fragmented_handshake_coalesced_setup_read_and_write_roundtrip(self):
        cr = bytes.fromhex('0300001611e00000000100c0010ac1020100c2020102')
        self.client.sendall(cr[:2])
        self.client.sendall(cr[2:])
        confirm = self.receive()
        self.assertEqual(confirm[1], 0xD0)
        self.assertEqual(len(confirm), confirm[0] + 1)
        address = b'\x12\x0a\x10\x02\x00\x02\x00\x01\x84\x00\x00\x00'
        setup = self.job(1, b'\xf0\x00\x00\x01\x00\x01\x01\xe0')
        read = self.job(2, b'\x04\x01' + address)
        self.client.sendall(setup + read)
        self.receive()
        response = self.receive()
        self.assertEqual(response[7:9], b'\x00\x02')  # sequence echo
        self.assertEqual(response[-2:], b'\x00\x00')
        self.client.sendall(self.job(3, b'\x05\x01' + address, b'\x00\x04\x00\x10\x12\x34'))
        self.assertEqual(self.receive()[-1:], b'\xff')
        self.client.sendall(self.job(4, b'\x04\x01' + address))
        self.assertEqual(self.receive()[-2:], b'\x12\x34')
        self.client.sendall(self.service._tpkt(bytes.fromhex('0680000100010000')))
        self.assertEqual(self.receive()[1], 0xC0)
        self.client.close()
        self.thread.join(3)
        records = [json.loads(line) for line in self.service.LOG_PATH.read_text().splitlines()]
        self.assertFalse(any(r['event'] == 'protocol_error' for r in records))
        self.assertTrue(any(r['event'] == 'disconnect' for r in records))
        self.assertTrue(any(r.get('data', {}).get('values_hex') == '1234' for r in records))
        self.assertEqual(len({r['event_id'] for r in records}), len(records))
