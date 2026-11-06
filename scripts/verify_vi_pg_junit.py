"""Fail closed when the dedicated engine-specific suite did not actually run."""
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def check(path, minimum=101):
    root=ET.parse(Path(path)).getroot()
    cases=root.findall('.//testcase')
    skipped=[c for c in cases if c.find('skipped') is not None]
    failed=[c for c in cases if c.find('failure') is not None or c.find('error') is not None]
    if len(cases)<minimum or skipped or failed:
        raise ValueError(f'engine coverage failed: cases={len(cases)} skipped={len(skipped)} failed={len(failed)} minimum={minimum}')
    return len(cases)

if __name__=='__main__':
    try: print(f'PostgreSQL engine cases executed: {check(sys.argv[1])}; no skips')
    except (IndexError,OSError,ET.ParseError,ValueError) as exc:
        print(f'PostgreSQL verification failed: {exc}',file=sys.stderr);sys.exit(1)
