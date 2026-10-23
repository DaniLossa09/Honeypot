import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.portscan_sensor import ScanDetector, parse_syn, scan_event
from backend.classifier import classify_attack
from backend.parsers import parse_portscan_line, read_incremental, validate_record


class PortScanSensorTest(unittest.TestCase):
    def test_parse_ipv4_ipv6_syn_and_reject_replies(self):
        for line, expected in [
            ('1.25 IP 192.0.2.1.50000 > 192.0.2.2.80: Flags [S], seq 1',
             ('192.0.2.1', '192.0.2.2', 50000, 80)),
            ('1.25 eth0 In IP6 2001:db8::1.50000 > 2001:db8::2.443: Flags [SEW], seq 1',
             ('2001:db8::1', '2001:db8::2', 50000, 443)),
        ]:
            self.assertEqual(parse_syn(line), expected)
        for line in ['invalid', '1 IP 192.0.2.1.50 > 192.0.2.2.80: Flags [S.]',
                     '1 IP 192.0.2.1.50 > 192.0.2.2.80: Flags [R]',
                     '1 IP 192.0.2.1.50 > 192.0.2.2.0: Flags [S]']:
            self.assertIsNone(parse_syn(line))

    def test_distinct_ports_window_and_cooldown(self):
        detector = ScanDetector(threshold=3, window=10, cooldown=60)
        for now in range(5):
            self.assertIsNone(detector.observe('a', 'b', 22, now))
        self.assertIsNone(detector.observe('a', 'b', 80, 5))
        self.assertEqual(detector.observe('a', 'b', 443, 6), [22, 80, 443])
        for port in range(1, 20):
            self.assertIsNone(detector.observe('a', 'b', port, 7))
        for port in [22, 80]:
            self.assertIsNone(detector.observe('a', 'b', port, 67))
        self.assertEqual(detector.observe('a', 'b', 443, 68), [22, 80, 443])
        slow = ScanDetector(threshold=3, window=10)
        for now, port in [(1, 22), (12, 80), (23, 443)]:
            self.assertIsNone(slow.observe('a', 'b', port, now))

    def test_source_destination_isolation_and_memory_bound(self):
        detector = ScanDetector(threshold=3, max_hosts=2)
        for src, dst, port in [('a','x',1), ('a','y',2), ('b','x',3)]:
            self.assertIsNone(detector.observe(src, dst, port, 1))
        self.assertEqual(len(detector.hosts), 2)
        self.assertNotIn(('a', 'x'), detector.hosts)
        detector.observe('c', 'x', 1, 100)
        self.assertEqual(len(detector.hosts), 1)

    def test_emitted_event_parser_classifier_and_incremental_replay(self):
        event = scan_event('192.0.2.1', '192.0.2.2', 50000, 443, [22,80,443], 10)
        record = parse_portscan_line(json.dumps(event))
        validate_record(record)
        self.assertEqual(record['source'], 'portscan')
        self.assertEqual(classify_attack(record), 'Port Scan')
        for port in (21, 22, 80, 443, 445, 3306):
            self.assertEqual(classify_attack({**record, 'port': port}), 'Port Scan')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'scan.jsonl'
            path.write_text(json.dumps(event) + '\n')
            records, offset = read_incremental('portscan', str(path), 0)
            self.assertEqual(len(records), 1)
            self.assertEqual(read_incremental('portscan', str(path), offset)[0], [])
        event['logtype'] = 3001
        with self.assertRaises(ValueError):
            parse_portscan_line(json.dumps(event))

    def test_local_address_filter_excludes_docker_bridges(self):
        from scripts.portscan_sensor import local_addresses
        rows = [{'ifname': name, 'addr_info': [{'family': 'inet', 'local': ip}]}
                for name, ip in [('eth0','192.0.2.2'), ('lo','127.0.0.1'),
                                 ('br-123','172.18.0.1'), ('veth123','172.18.0.2')]]
        with patch('scripts.portscan_sensor.subprocess.check_output', return_value=json.dumps(rows)):
            self.assertEqual(local_addresses(), {'192.0.2.2', '127.0.0.1'})


if __name__ == '__main__':
    unittest.main()
