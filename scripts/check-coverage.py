#!/usr/bin/env python3
"""Check the existing 80% gate against the real Tarpaulin summary."""
from decimal import Decimal
import argparse
import os
from pathlib import Path
import re

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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('filename')
    parser.add_argument('--print-percentage', action='store_true',
                        help='parse the CD report without changing its reporting-only policy')
    args = parser.parse_args()
    if args.print_percentage:
        print(coverage_percent(Path(args.filename).read_text()))
    else:
        main(args.filename)
