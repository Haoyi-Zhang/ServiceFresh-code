"""Regenerate presentation data without new experiments or frozen-data writes."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest

from report import generate

ROOT = Path(__file__).resolve().parents[1]


class ReportTests(unittest.TestCase):
    def test_reference_tables_regenerate_exact_bytes(self):
        expected = ROOT / "results/paper-data"
        names = sorted(path.name for path in expected.iterdir() if path.is_file())
        self.assertEqual(len(names), 9)
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            output = Path(directory)
            generate(ROOT / "results/reference", output)
            self.assertEqual(sorted(path.name for path in output.iterdir()), names)
            for name in names:
                with self.subTest(file=name):
                    self.assertEqual((output / name).read_bytes(),
                                     (expected / name).read_bytes())


if __name__ == "__main__":
    unittest.main()
