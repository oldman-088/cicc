"""Validate the dedicated engine CI guard cannot silently pass a skipped suite."""
import pytest
from scripts.verify_vi_pg_junit import check

def test_guard_rejects_skips_and_insufficient_engine_cases(tmp_path):
    p=tmp_path/'results.xml'
    p.write_text('<testsuites><testsuite><testcase/><testcase><skipped/></testcase></testsuite></testsuites>')
    with pytest.raises(ValueError,match='skipped=1'): check(p,minimum=2)
    p.write_text('<testsuites><testsuite><testcase/></testsuite></testsuites>')
    with pytest.raises(ValueError,match='minimum=2'): check(p,minimum=2)
    assert check(p,minimum=1)==1
    p.write_text('<testsuite><testcase><failure/></testcase></testsuite>')
    with pytest.raises(ValueError,match='failed=1'): check(p,minimum=1)
