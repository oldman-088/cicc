"""No live calls: terminal, transport and database errors are simulated."""
from app.connectors import nvd_cli


def test_requires_valid_cve_confirmation_database_and_terminal(monkeypatch, capsys):
    monkeypatch.delenv('DATABASE_URL', raising=False)
    assert nvd_cli.main(['not-a-cve', '--confirm-live-fetch']) == 2
    assert nvd_cli.main(['CVE-2099-0001']) == 2
    monkeypatch.setenv('DATABASE_URL', 'postgresql+psycopg://example')
    monkeypatch.setattr(nvd_cli.sys.stdin, 'isatty', lambda: False)
    assert nvd_cli.main(['CVE-2099-0001', '--confirm-live-fetch']) == 2
    assert 'terminal' in capsys.readouterr().err


def test_wrong_database_rejected_before_token_or_fetch(monkeypatch, capsys):
    monkeypatch.setenv('DATABASE_URL', 'sqlite:///unused.db')
    monkeypatch.setattr(nvd_cli.sys.stdin, 'isatty', lambda: True)
    monkeypatch.setattr(nvd_cli.sys.stderr, 'isatty', lambda: True)
    def forbidden(*args, **kwargs): raise AssertionError('must not be called')
    monkeypatch.setattr(nvd_cli.getpass, 'getpass', forbidden)
    monkeypatch.setattr(nvd_cli, 'synchronize', forbidden)
    assert nvd_cli.main(['CVE-2099-0001', '--confirm-live-fetch']) == 1
    assert 'Lookup did not complete' in capsys.readouterr().err
