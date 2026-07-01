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


if __name__ == "__main__":
    unittest.main()
