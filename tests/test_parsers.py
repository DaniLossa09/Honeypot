import tempfile
import unittest
from pathlib import Path

from backend.parsers import _read_new_lines


class ReadNewLinesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "log.json"

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, text: str) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(text)

    def test_partial_trailing_line_is_not_consumed(self):
        # riga completa + riga parziale (log ancora in scrittura)
        self._write('{"a": 1}\n{"a": 2}')
        lines, offset = _read_new_lines(self.path, 0)
        self.assertEqual(lines, ['{"a": 1}'])
        # offset si ferma dopo la prima newline, non oltre la riga parziale
        self.assertEqual(offset, len('{"a": 1}\n'))

        # completiamo la seconda riga: ora viene letta senza perdite
        self._write('\n')
        lines2, offset2 = _read_new_lines(self.path, offset)
        self.assertEqual(lines2, ['{"a": 2}'])
        self.assertEqual(offset2, len('{"a": 1}\n{"a": 2}\n'))

    def test_no_complete_line_keeps_offset(self):
        self._write('{"partial": ')
        lines, offset = _read_new_lines(self.path, 0)
        self.assertEqual(lines, [])
        self.assertEqual(offset, 0)

    def test_truncated_file_resets_offset(self):
        self._write('{"a": 1}\n')
        # offset oltre la dimensione del file (rotazione/troncamento) → riparte da 0
        lines, offset = _read_new_lines(self.path, 9999)
        self.assertEqual(lines, ['{"a": 1}'])

    def test_missing_file(self):
        missing = Path(self.tmp.name) / "nope.json"
        self.assertEqual(_read_new_lines(missing, 0), ([], 0))


class RotationAndSchemaTest(unittest.TestCase):
    def test_replacement_larger_than_saved_offset(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'log'
            path.write_bytes(b'old\n')
            state = {}
            _, offset = _read_new_lines(path, 0, state)
            replacement = Path(td) / 'new'
            replacement.write_bytes(b'first\nsecond\n')
            replacement.replace(path)
            lines, _ = _read_new_lines(path, offset, state)
            self.assertEqual(lines, ['first', 'second'])

    def test_copytruncate_regrown_beyond_offset(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'log'
            path.write_bytes(b'old\n')
            state = {}
            _, offset = _read_new_lines(path, 0, state)
            path.write_bytes(b'first\nsecond\n')
            lines, _ = _read_new_lines(path, offset, state)
            self.assertEqual(lines, ['first', 'second'])

    def test_legacy_offset_is_adopted_without_replay(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'log'
            path.write_bytes(b'already consumed\n')
            state = {}
            lines, offset = _read_new_lines(path, path.stat().st_size, state)
            self.assertEqual(lines, [])
            self.assertEqual(state['offset'], offset)
            self.assertIn('identity', state)

    def test_invalid_schema_does_not_hide_following_valid_event(self):
        import json
        from backend.parsers import read_incremental
        valid = {'utc_time': '2026-10-20 16:36:18.617241', 'src_host': '::1',
                 'dst_port': 443, 'logtype': 3001,
                 'logdata': {'USERNAME': 'audit', 'PASSWORD': 'probe'}}
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'log'
            path.write_text('[1,2]\n' + json.dumps({**valid, 'logdata': []}) + '\n' +
                            json.dumps(valid) + '\n')
            with self.assertLogs('backend.parsers', level='WARNING') as logs:
                records, offset = read_incremental('opencanary', str(path), 0)
            self.assertEqual(len(records), 1)
            self.assertEqual(offset, path.stat().st_size)
            self.assertEqual(len(logs.output), 2)
            self.assertEqual(records[0]['timestamp'], '2026-10-20T16:36:18.617241+00:00')
            self.assertEqual(records[0]['ip'], '::1')

    def test_invalid_field_types_ports_and_timestamps_are_rejected(self):
        import json
        from backend.parsers import parse_opencanary_line
        valid = {'utc_time': '2026-10-20 16:36:18', 'src_host': '127.0.0.1',
                 'dst_port': 80, 'logtype': 3000, 'logdata': {'PATH': '/'}}
        for override in [{'dst_port': True}, {'dst_port': -1}, {'src_host': 'invalid'},
                         {'logtype': '3000'}, {'utc_time': 'invalid'},
                         {'logdata': {'PATH': []}}, {'logdata': {'USERNAME': {}}}]:
            with self.subTest(override=override), self.assertRaises(ValueError):
                parse_opencanary_line(json.dumps({**valid, **override}))

    def test_unknown_logtype_is_preserved_and_reported(self):
        import json
        from backend.parsers import parse_opencanary_line
        with self.assertLogs('backend.parsers', level='WARNING'):
            record = parse_opencanary_line(json.dumps({
                'utc_time': '2026-10-20 16:36:18', 'src_host': '127.0.0.1',
                'dst_port': 80, 'logtype': 99999, 'logdata': {}}))
        self.assertEqual(record['event_type'], 99999)


class CowrieFtpSchemaTest(unittest.TestCase):
    def test_session_params_message_array_is_validated_without_losing_payload(self):
        import json
        from backend.parsers import parse_cowrie_line, validate_record
        raw = {'timestamp': '2026-10-20T16:00:00Z', 'src_ip': '127.0.0.1',
               'eventid': 'cowrie.session.params', 'message': []}
        record = parse_cowrie_line(json.dumps(raw))
        validate_record(record)
        self.assertEqual(record['raw_event']['message'], [])
        self.assertIsInstance(record['message'], str)
        with self.assertRaises(ValueError):
            parse_cowrie_line(json.dumps({**raw, 'message': [{}]}))

    def test_telnet_negotiation_is_not_a_shell_command(self):
        import json
        from backend.parsers import parse_cowrie_line
        record = parse_cowrie_line(json.dumps({
            'timestamp': '2026-10-20T16:00:00Z', 'src_ip': '::1',
            'eventid': 'cowrie.telnet.option', 'command': 'DONT', 'protocol': 'telnet',
        }))
        self.assertIsNone(record['command'])
        self.assertEqual(record['port'], 23)
        self.assertEqual(record['raw_event']['command'], 'DONT')

    def test_invalid_fields_are_rejected_for_both_sources(self):
        import json
        from backend.parsers import parse_cowrie_line, parse_ftp_line
        base = {'timestamp': '2026-10-20T16:00:00Z', 'src_ip': '127.0.0.1',
                'eventid': 'cowrie.command.input', 'command': 'USER', 'protocol': 'ssh'}
        for parser in (parse_cowrie_line, parse_ftp_line):
            for override in ({'src_ip': 'invalid'}, {'src_port': True},
                             {'dst_port': 70000}, {'command': []},
                             {'username': {}}, {'timestamp': 'invalid'}):
                with self.subTest(parser=parser.__name__, override=override), self.assertRaises(ValueError):
                    parser(json.dumps({**base, **override}))

    def test_bad_record_is_rejected_at_classifier_and_db_boundaries(self):
        import json
        from backend.parsers import parse_ftp_line
        from backend.classifier import classify_attack
        from backend.db import insert_raw_event
        record = parse_ftp_line(json.dumps({
            'timestamp': '2026-10-20T16:00:00Z', 'src_ip': '127.0.0.1', 'command': 'PASS'}))
        record['username'] = {'unexpected': 'object'}
        with self.assertRaises(ValueError):
            classify_attack(record)
        with self.assertRaises(ValueError):
            insert_raw_event(record)



if __name__ == "__main__":
    unittest.main()
