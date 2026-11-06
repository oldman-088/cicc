"""Offline checks of configuration only; never an actual-host integration test."""
import pytest
from host_integration.test_agent1_gateway_contract import host_harness_module, HostConfigurationError


def test_absent_host_configuration_is_the_only_normal_skip_condition():
    assert host_harness_module({}) is None
    assert host_harness_module({'CICC_TI_HOST_ISOLATED':'0'}) is None


@pytest.mark.parametrize('values',[
    {'CICC_TI_HOST_ISOLATED':'1'},
    {'CICC_TI_HOST_ISOLATED':'1','CICC_TI_HOST_TEST_HARNESS':'   '},
    {'CICC_TI_HOST_TEST_HARNESS':'example_harness'},
    {'CICC_TI_HOST_ISOLATED':'0','CICC_TI_HOST_TEST_HARNESS':'example_harness'},
])
def test_partial_host_configuration_is_error_not_skip(values):
    with pytest.raises(HostConfigurationError): host_harness_module(values)


def test_complete_host_configuration_preserves_module_name():
    assert host_harness_module({'CICC_TI_HOST_ISOLATED':'1','CICC_TI_HOST_TEST_HARNESS':'example_harness'})=='example_harness'


def test_partial_real_pytest_configuration_errors_instead_of_skipping():
    import os, subprocess, sys
    env=os.environ.copy()
    env.pop('CICC_TI_HOST_TEST_HARNESS',None)
    env['CICC_TI_HOST_ISOLATED']='1'
    result=subprocess.run([sys.executable,'-m','pytest','-q',
        'apps/threat_intelligence/tests/host_integration/test_agent1_gateway_contract.py::test_actual_gateway_create_postgres_and_audit'],
        env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=20)
    assert result.returncode != 0 and 'requires an approved harness module' in result.stdout
    assert '1 skipped' not in result.stdout
