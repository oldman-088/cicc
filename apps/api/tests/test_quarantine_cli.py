"""Synthetic data only; no production storage or operator audit."""
import json
import os
import subprocess
import sys
from app import quarantine_cli


def test_cli_preflight_and_sanitized_errors(monkeypatch,capsys):
    monkeypatch.delenv('CICC_QUARANTINE_DIRECTORY',raising=False)
    assert quarantine_cli.main(['--confirm-read-only'])==2
    monkeypatch.setenv('CICC_QUARANTINE_DIRECTORY','/secret/path')
    assert quarantine_cli.main([])==2
    assert quarantine_cli.main(['--confirm-read-only','--max-entries','0'])==2
    def fail(*args,**kwargs): raise OSError('/secret/path private')
    monkeypatch.setattr(quarantine_cli,'inventory',fail)
    assert quarantine_cli.main(['--confirm-read-only'])==1
    output=capsys.readouterr()
    assert '/secret/path' not in output.err+output.out


def test_cli_subprocess_read_only_and_no_content_exposure(tmp_path):
    path=tmp_path/'private'; path.mkdir(mode=0o700)
    item=path/('tmp-'+'a'*64); item.write_bytes(b'private synthetic fixture'); item.chmod(0o600)
    (path/'unrelated').write_bytes(b'other synthetic fixture')
    before={p.name:p.read_bytes() for p in path.iterdir()}
    result=subprocess.run([sys.executable,'-m','app.quarantine_cli','--confirm-read-only','--max-entries','100'],
        env={**os.environ,'CICC_QUARANTINE_DIRECTORY':str(path)},capture_output=True,text=True,check=True)
    body=json.loads(result.stdout)
    assert body['examined']==2 and not body['truncated'] and len(body['items'])==1
    assert body['items'][0]['object_id']=='a'*64 and body['items'][0]['kind']=='temporary'
    assert 'not a complete scan' in body['notice'] and 'private synthetic fixture' not in result.stdout
    assert str(path) not in result.stdout+result.stderr
    assert {p.name:p.read_bytes() for p in path.iterdir()}==before


def test_cli_rejects_busy_stage_and_does_not_mutate(tmp_path):
    import io
    import pytest
    from app.evidence_quarantine import stage_stream
    path=tmp_path/'private'; path.mkdir(mode=0o700)
    existing=path/'unrelated'; existing.write_bytes(b'synthetic sentinel')
    class Active:
        def read(self,n):
            result=subprocess.run([sys.executable,'-m','app.quarantine_cli','--confirm-read-only'],
                env={**os.environ,'CICC_QUARANTINE_DIRECTORY':str(path)},capture_output=True,text=True,check=False)
            assert result.returncode==1 and not result.stdout and 'busy' in result.stderr
            assert str(path) not in result.stderr
            raise OSError('synthetic stop')
    with pytest.raises(OSError,match='synthetic stop'):
        stage_stream(str(path),Active(),max_bytes=10)
    assert [(p.name,p.read_bytes()) for p in path.iterdir()]==[('unrelated',b'synthetic sentinel')]


def test_cli_rejects_insecure_or_missing_directory_without_disclosing_paths(tmp_path):
    path=tmp_path/'private'; path.mkdir(mode=0o755); path.chmod(0o755)
    for candidate in (path,tmp_path/'missing'):
        result=subprocess.run([sys.executable,'-m','app.quarantine_cli','--confirm-read-only'],
            env={**os.environ,'CICC_QUARANTINE_DIRECTORY':str(candidate)},capture_output=True,text=True,check=False)
        assert result.returncode==1 and not result.stdout and 'could not be completed' in result.stderr
        assert str(candidate) not in result.stderr
