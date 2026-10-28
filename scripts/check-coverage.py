#!/usr/bin/env python3
"""Check the existing 80% gate against the real Tarpaulin summary."""
from decimal import Decimal
import os
from pathlib import Path
import re
import sys

MINIMUM = Decimal('80')
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')


def coverage_percent(text):
    values = re.findall(r'(?<![\d.])(\d+(?:\.\d+)?)%\s+coverage\b', ANSI.sub('', text))
    if not values:
        raise ValueError('Tarpaulin coverage summary missing')
    value = Decimal(values[-1])
    if not Decimal('0') <= value <= Decimal('100'):
        raise ValueError('Invalid coverage percentage')
    return value


def main(filename):
    value = coverage_percent(Path(filename).read_text())
    message = f'Coverage: {value}% (minimum {MINIMUM}%)'
    print(message)
    if summary := os.environ.get('GITHUB_STEP_SUMMARY'):
        with Path(summary).open('a') as destination:
            destination.write(f'### {message}\n')
    if value < MINIMUM:
        raise SystemExit(f'{value}% is below the unchanged {MINIMUM}% threshold')


if __name__ == '__main__':
    main(sys.argv[1])
