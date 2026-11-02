"""Validate the lock consistency check without installing dependencies."""
import importlib.util
from pathlib import Path
import pytest

path = Path(__file__).resolve().parents[3] / 'scripts' / 'check_python_locks.py'
spec = importlib.util.spec_from_file_location('check_python_locks', path)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

def test_lock_check_rejects_pin_drift_and_duplicate(tmp_path, monkeypatch):
    monkeypatch.setattr(checker, 'ROOT', tmp_path)
    (tmp_path / 'requirements.txt').write_text('core[extra]==1.0\n')
    (tmp_path / 'requirements-dev.txt').write_text('-r requirements.txt\npytest==9.0\n')
    (tmp_path / 'requirements.lock').write_text('core==1.0 \\\n    --hash=sha256:unused\n')
    (tmp_path / 'requirements-dev.lock').write_text('core==1.0\npytest==9.0\n')
    checker.main()
    (tmp_path / 'requirements-dev.lock').write_text('core==1.1\npytest==9.0\n')
    with pytest.raises(ValueError, match='differs'): checker.main()
    (tmp_path / 'requirements.lock').write_text('core==1.0\nCORE==1.0\n')
    with pytest.raises(ValueError, match='duplicate'): checker.main()
