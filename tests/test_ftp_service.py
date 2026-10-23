"""Regressioni del framing con socket TCP reali e log isolati in /tmp."""
import importlib.util
import json
import select
import socket
import tempfile
import threading
import unittest
from pathlib import Path


class FtpServiceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = Path(self.tmp.name) / 'ftp.json'
        path = Path(__file__).resolve().parents[1] / 'honeypots/dionaea/ftp_honeypot.py'
        spec = importlib.util.spec_from_file_location('ftp_service_under_test', path)
        self.service = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.service)
        self.service.LOG_PATH = str(self.log_path)
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.listener.settimeout(3)
        def serve():
            conn, addr = self.listener.accept()
            self.service.handle_client(conn, addr)
        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()
        self.client = socket.create_connection(self.listener.getsockname(), timeout=3)
        self.stream = self.client.makefile('rb')
        self.assertTrue(self.stream.readline().startswith(b'220 '))

    def tearDown(self):
        self.stream.close()
        self.client.close()
        self.listener.close()
        self.thread.join(3)
        self.tmp.cleanup()

    def records(self):
        self.thread.join(3)
        self.assertFalse(self.thread.is_alive())
        return [json.loads(line) for line in self.log_path.read_text().splitlines()]

    def test_coalesced_commands_keep_separate_credentials_and_session(self):
        self.client.sendall(b'USER audit\r\nPASS probe\r\nQUIT\r\n')
        for code in (b'331 ', b'530 ', b'221 '):
            self.assertTrue(self.stream.readline().startswith(code))
        rows = self.records()
        self.assertEqual([r['command'] for r in rows], ['CONNECT', 'USER', 'PASS', 'QUIT', 'DISCONNECT'])
        password = rows[2]
        self.assertEqual((password['username'], password['password']), ('audit', 'probe'))
        self.assertEqual(len({r['session'] for r in rows}), 1)
        self.assertEqual(password['src_port'], self.client.getsockname()[1])
        self.assertEqual(password['dst_port'], self.listener.getsockname()[1])

    def test_fragmented_command_waits_for_crlf(self):
        self.client.sendall(b'USER ')
        self.assertFalse(select.select([self.client], [], [], 0.1)[0])
        self.client.sendall(b'audit\r\nQUIT\r\n')
        self.assertTrue(self.stream.readline().startswith(b'331 '))
        self.assertTrue(self.stream.readline().startswith(b'221 '))
        self.assertEqual([r['command'] for r in self.records()], ['CONNECT', 'USER', 'QUIT', 'DISCONNECT'])

    def test_transfers_and_data_modes_are_explicitly_denied(self):
        for command in ('PASV', 'EPSV', 'PORT 127,0,0,1,1,1', 'EPRT |1|127.0.0.1|21|',
                        'LIST', 'RETR README.txt', 'STOR audit.txt', 'APPE audit.txt'):
            self.client.sendall(command.encode() + b'\r\n')
            self.assertTrue(self.stream.readline().startswith(b'530 '))
        self.client.sendall(b'QUIT\r\n')
        self.assertTrue(self.stream.readline().startswith(b'221 '))
        self.assertEqual(len(self.records()), 11)

    def test_oversized_command_is_logged_and_closed(self):
        self.client.sendall(b'A' * (self.service.MAX_COMMAND_BYTES + 1))
        self.assertTrue(self.stream.readline().startswith(b'500 '))
        self.assertIn('INVALID', [r['command'] for r in self.records()])
