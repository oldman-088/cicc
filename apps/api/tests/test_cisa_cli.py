from app.connectors import cisa_cli

def test_requires_confirmation_database_and_tty(monkeypatch, capsys):
    monkeypatch.delenv('DATABASE_URL', raising=False)
    assert cisa_cli.main([]) == 2
    monkeypatch.setenv('DATABASE_URL', 'postgresql+psycopg://example')
    monkeypatch.setattr(cisa_cli.sys.stdin, 'isatty', lambda: False)
    assert cisa_cli.main(['--confirm-live-fetch']) == 2
    assert 'terminal' in capsys.readouterr().err

def test_errors_redacted_and_no_network_on_wrong_database(monkeypatch, capsys):
    monkeypatch.setenv('DATABASE_URL', 'sqlite:///unused.db')
    monkeypatch.setattr(cisa_cli.sys.stdin, 'isatty', lambda: True)
    monkeypatch.setattr(cisa_cli.sys.stderr, 'isatty', lambda: True)
    monkeypatch.setattr(cisa_cli.getpass, 'getpass', lambda _: 'super-secret-token')
    monkeypatch.setattr(cisa_cli, 'synchronize', lambda *a, **k: (_ for _ in ()).throw(AssertionError('must not run')))
    assert cisa_cli.main(['--confirm-live-fetch']) == 1
    output = capsys.readouterr()
    assert 'super-secret-token' not in output.out + output.err
    assert 'Synchronization did not complete' in output.err
