"""Conservative structural check of the CVSS 3.1 *base-only* vector subset.

Not a score calculator, severity classification or finding of applicability.
"""
BASE={'AV':{'N','A','L','P'},'AC':{'L','H'},'PR':{'N','L','H'},'UI':{'N','R'},
      'S':{'U','C'},'C':{'N','L','H'},'I':{'N','L','H'},'A':{'N','L','H'}}

def check_cvss31_base_vector(value):
    if not isinstance(value,str) or not value or len(value)>1024:
        raise ValueError('bounded vector text required')
    if not value.startswith('CVSS:3.1/'):
        return {'status':'unsupported','version':None,'reason':'only CVSS 3.1 base-only vectors are checked'}
    metrics={};extra=False
    for part in value[len('CVSS:3.1/'):].split('/'):
        pair=part.split(':')
        if len(pair)!=2 or not pair[0] or not pair[1]: return {'status':'invalid','version':'3.1','reason':'malformed metric'}
        key,val=pair
        if key in metrics: return {'status':'invalid','version':'3.1','reason':'duplicate metric'}
        metrics[key]=val
        if key not in BASE: extra=True
        elif val not in BASE[key]: return {'status':'invalid','version':'3.1','reason':'invalid base metric value'}
    if not set(BASE).issubset(metrics): return {'status':'invalid','version':'3.1','reason':'missing base metric'}
    if extra: return {'status':'unsupported','version':'3.1','reason':'temporal/environmental or unknown metrics not checked'}
    return {'status':'valid_base_structure','version':'3.1','reason':'base metric structure only; score not computed'}
