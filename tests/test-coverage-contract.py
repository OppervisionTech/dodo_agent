from decimal import Decimal
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('coverage_check', ROOT / 'scripts/check-coverage.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CoverageContractTests(unittest.TestCase):
    def test_official_tarpaulin_format_without_a_space_before_percent(self):
        self.assertEqual(module.coverage_percent('85.71% coverage, 6/7 lines covered'), Decimal('85.71'))
        self.assertEqual(module.coverage_percent('\x1b[32m80.00%\x1b[0m coverage, 80/100 lines covered'), Decimal('80'))

    def test_missing_or_invalid_report_is_not_success(self):
        for text in ['no summary', '101% coverage', 'NaN% coverage']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                module.coverage_percent(text)

    def test_actual_cli_keeps_eighty_percent_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'tarpaulin.log'
            for value, succeeds in [('79.99', False), ('80.00', True), ('85.71', True)]:
                report.write_text(f'{value}% coverage, covered/total lines\n')
                result = subprocess.run([sys.executable, str(ROOT/'scripts/check-coverage.py'), str(report)], capture_output=True)
                self.assertEqual(result.returncode == 0, succeeds)

    def test_cd_reporting_mode_uses_same_parser_without_adding_a_new_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'tarpaulin.log'
            command = [sys.executable, str(ROOT/'scripts/check-coverage.py'), '--print-percentage', str(report)]
            report.write_text('79.99% coverage, 7999/10000 lines covered\n')
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.strip(), '79.99')
            report.write_text('missing summary\n')
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
