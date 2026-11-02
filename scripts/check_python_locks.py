#!/usr/bin/env python3
"""Check direct pins and runtime/dev lock agreement (not a resolver)."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1] / 'apps' / 'api'
PIN = re.compile(r'^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?==([^\s\\;]+)')

def pins(path):
    result = {}
    for line in path.read_text().splitlines():
        match = PIN.match(line.strip())
        if match:
            name = re.sub(r'[-_.]+', '-', match.group(1)).lower()
            if name in result:
                raise ValueError(f'duplicate pin: {name}')
            result[name] = match.group(2)
    return result

def main():
    runtime = pins(ROOT / 'requirements.lock')
    dev = pins(ROOT / 'requirements-dev.lock')
    direct_runtime = pins(ROOT / 'requirements.txt')
    direct_dev = pins(ROOT / 'requirements-dev.txt')
    for name, version in direct_runtime.items():
        if runtime.get(name) != version or dev.get(name) != version:
            raise ValueError(f'runtime direct pin differs from lock: {name}')
    for name, version in direct_dev.items():
        if dev.get(name) != version:
            raise ValueError(f'dev direct pin differs from lock: {name}')
    for name, version in runtime.items():
        if dev.get(name) != version:
            raise ValueError(f'runtime/dev locks differ: {name}')
    print('Python direct pins and runtime/dev locks agree.')

if __name__ == '__main__':
    try:
        main()
    except ValueError as exc:
        sys.exit(str(exc))
