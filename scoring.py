"""Explainable illustrative exposure scoring, not CVSS or effective AWS risk."""

def explain_finding(finding, environment):
    nodes = {n['id']: n for n in environment['nodes']}
    target = nodes[finding['target']]
    source = nodes[finding['source']]
    impact = {'bucket':65, 'database':80, 'secret':90}[target['kind']]
    exposure = 15 if source['kind'] == 'internet' else 5
    hops = len(finding['path']) - 2
    hop_adjustment = -4 * hops
    score = min(100, impact + exposure + hop_adjustment)
    return {'score':score, 'factors':{'sensitive_asset_impact':impact,'source_exposure':exposure,'intermediate_hop_adjustment':hop_adjustment}, 'methodology':'Illustrative score = min(100, target impact + entry exposure - 4 per intermediate hop). Not CVSS; no exploitability verification.', 'recommendations':['Review and restrict the entry-point relationship.','Apply least privilege to identities along this path.','Verify effective permissions and network controls in AWS before making production changes.']}

def enrich(result, environment):
    for f in result['findings']:
        f['risk_explanation'] = explain_finding(f, environment)
    return result
