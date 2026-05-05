import json
import unittest

from backend.classifier import classify_attack, classify_signal
from backend.parsers import parse_cowrie_line, parse_ftp_line, parse_opencanary_line


class DetectionRulesTest(unittest.TestCase):
    def test_cowrie_noise_failed_login_success_and_commands(self):
        connect = parse_cowrie_line(json.dumps({
            "eventid": "cowrie.session.connect",
            "src_ip": "192.0.2.10",
            "timestamp": "2026-04-29T18:00:00Z",
            "protocol": "ssh",
        }))
        failed = parse_cowrie_line(json.dumps({
            "eventid": "cowrie.login.failed",
            "username": "root",
            "password": "wrong",
            "src_ip": "192.0.2.10",
            "timestamp": "2026-04-29T18:01:00Z",
            "protocol": "ssh",
        }))
        success = parse_cowrie_line(json.dumps({
            "eventid": "cowrie.login.success",
            "username": "admin",
            "password": "password",
            "src_ip": "192.0.2.10",
            "timestamp": "2026-04-29T18:02:00Z",
            "protocol": "ssh",
        }))
        exit_command = parse_cowrie_line(json.dumps({
            "eventid": "cowrie.command.input",
            "input": "exit",
            "src_ip": "192.0.2.10",
            "timestamp": "2026-04-29T18:03:00Z",
            "protocol": "ssh",
        }))
        command = parse_cowrie_line(json.dumps({
            "eventid": "cowrie.command.input",
            "input": "whoami",
            "src_ip": "192.0.2.10",
            "timestamp": "2026-04-29T18:04:00Z",
            "protocol": "ssh",
        }))

        self.assertIsNone(classify_attack(connect))
        self.assertIsNone(classify_signal(connect))
        self.assertIsNone(classify_attack(failed))
        self.assertEqual(classify_signal(failed), "Credential Attack")
        self.assertEqual(classify_attack(success), "Unauthorized Login")
        self.assertIsNone(classify_attack(exit_command))
        self.assertEqual(classify_attack(command), "Post-Login Activity")

    def test_opencanary_login_is_signal_but_web_attacks_are_incidents(self):
        login = parse_opencanary_line(json.dumps({
            "dst_port": 80,
            "logtype": 3001,
            "src_host": "192.0.2.20",
            "logdata": {
                "PATH": "/login",
                "USERNAME": "client",
                "PASSWORD": "secret",
            },
        }))
        sql_injection = parse_opencanary_line(json.dumps({
            "dst_port": 80,
            "logtype": 3000,
            "src_host": "192.0.2.20",
            "logdata": {
                "PATH": "/search?q=1 union select password from users",
            },
        }))
        xss = parse_opencanary_line(json.dumps({
            "dst_port": 443,
            "logtype": 3000,
            "src_host": "192.0.2.20",
            "logdata": {
                "PATH": "/profile?name=<script>alert(1)</script>",
            },
        }))
        normal_page = parse_opencanary_line(json.dumps({
            "dst_port": 80,
            "logtype": 3000,
            "src_host": "192.0.2.20",
            "logdata": {
                "PATH": "/index.html",
            },
        }))

        self.assertIsNone(classify_attack(login))
        self.assertEqual(classify_signal(login), "Credential Attack")
        self.assertEqual(classify_attack(sql_injection), "SQL Injection")
        self.assertEqual(classify_attack(xss), "XSS Attack")
        self.assertIsNone(classify_attack(normal_page))
        self.assertIsNone(classify_signal(normal_page))

    def test_ftp_credentials_are_threshold_signals_and_transfers_are_incidents(self):
        password = parse_ftp_line(json.dumps({
            "timestamp": "2026-04-29T18:00:00",
            "src_ip": "192.0.2.30",
            "command": "PASS",
            "argument": "secret",
        }))
        pwd = parse_ftp_line(json.dumps({
            "timestamp": "2026-04-29T18:01:00",
            "src_ip": "192.0.2.30",
            "command": "PWD",
        }))
        upload = parse_ftp_line(json.dumps({
            "timestamp": "2026-04-29T18:02:00",
            "src_ip": "192.0.2.30",
            "command": "STOR",
            "argument": "payload.txt",
        }))

        self.assertIsNone(classify_attack(password))
        self.assertEqual(classify_signal(password), "Credential Attack")
        self.assertIsNone(classify_attack(pwd))
        self.assertIsNone(classify_signal(pwd))
        self.assertEqual(classify_attack(upload), "FTP Attack")


if __name__ == "__main__":
    unittest.main()
