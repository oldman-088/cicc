import pytest
from apps.threat_intelligence.cvss_vector_checks import check_cvss31_base_vector

BASE='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'

def test_base_only_structure_is_checked_not_a_score_or_applicability():
    result=check_cvss31_base_vector(BASE)
    assert result['status']=='valid_base_structure' and 'score not computed' in result['reason']
    assert 'score' not in result and 'vulnerable' not in result

@pytest.mark.parametrize('vector', [BASE+'/AV:L',BASE.replace('/A:H',''),BASE.replace('AV:N','AV:Q'),BASE+'/broken'])
def test_invalid_base_vectors_are_not_valid(vector):
    assert check_cvss31_base_vector(vector)['status']=='invalid'

def test_other_versions_and_extensions_remain_unsupported():
    assert check_cvss31_base_vector(BASE+'/E:F')['status']=='unsupported'
    assert check_cvss31_base_vector('CVSS:4.0/fixture')['status']=='unsupported'
    with pytest.raises(ValueError): check_cvss31_base_vector('x'*1025)
