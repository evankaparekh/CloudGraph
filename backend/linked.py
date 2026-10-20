"""Conservative IAM-aware overlay for synthetic cloud graphs.

Only unconditional identity-policy Action/Resource Allow and explicit Deny are
modeled. This is NOT an AWS effective-permission or exploitation simulator.
"""
import fnmatch
from copy import deepcopy
from .engine import analyze, validate_environment


def _matches(value, patterns):
    if isinstance(patterns, str):
        patterns = [patterns]
    return isinstance(patterns, list) and all(isinstance(p, str) for p in patterns) and any(fnmatch.fnmatchcase(value.lower(), p.lower()) for p in patterns)


def evaluate(policy, action, resource):
    if not isinstance(policy, dict):
        return 'unknown', 'No identity policy supplied'
    statements = policy.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or len(statements) > 100:
        return 'unknown', 'Invalid or oversized policy'
    allowed = False
    uncertain = False
    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get('Effect') not in ('Allow', 'Deny'):
            uncertain = True
            continue
        if 'NotAction' in stmt or 'NotResource' in stmt or 'Principal' in stmt or 'NotPrincipal' in stmt:
            uncertain = True
            continue
        if not _matches(action, stmt.get('Action')) or not _matches(resource, stmt.get('Resource')):
            continue
        if 'Condition' in stmt:
            uncertain = True
            continue
        if stmt['Effect'] == 'Deny':
            return 'denied', 'Matching unconditional explicit Deny'
        allowed = True
    if uncertain:
        return 'unknown', 'Conditional or unsupported statement needs AWS evaluation'
    if allowed:
        return 'potential', 'Matching identity-policy Allow; other AWS controls not evaluated'
    return 'denied', 'No matching identity-policy Allow in supplied document'


def linked_analysis(environment, policies, disabled_edges=None):
    validate_environment(environment)
    if not isinstance(policies, dict) or len(policies) > 250:
        raise ValueError('policies must be an object keyed by node ID (maximum 250)')
    if disabled_edges is None:
        disabled_edges = []
    if not isinstance(disabled_edges, list) or any(type(i) is not int or i < 0 or i >= len(environment['edges']) for i in disabled_edges):
        raise ValueError('disabled_edges must contain valid edge indices')
    graph = deepcopy(environment)
    nodes = {n['id'] for n in graph['nodes']}
    if any(key not in nodes for key in policies):
        raise ValueError('Every policy key must reference an existing node')
    decisions = []
    for i, edge in enumerate(graph['edges']):
        if i in disabled_edges or not edge.get('enabled', True):
            edge['enabled'] = False
            decisions.append({'index': i, 'status': 'disabled', 'reason': 'Disabled by configuration or simulation'})
            continue
        action, resource = edge.get('iam_action'), edge.get('iam_resource')
        if action is None and resource is None:
            decisions.append({'index': i, 'status': 'unmodeled', 'reason': 'Existing synthetic relationship; IAM not evaluated'})
            continue
        if not isinstance(action, str) or not action or not isinstance(resource, str) or not resource:
            raise ValueError(f'Edge {i} must have nonempty iam_action and iam_resource')
        status, reason = evaluate(policies.get(edge['source']), action, resource)
        # Fail closed for definitive modeled paths; unknown edges are never asserted reachable.
        if status != 'potential':
            edge['enabled'] = False
        decisions.append({'index': i, 'status': status, 'reason': reason, 'action': action, 'resource': resource})
    result = analyze(graph)
    result['findings'] = [{**f, 'iam_note': 'Potential modeled path only; identity-policy Allow does not establish effective AWS authorization.'} for f in result['findings']]
    result['decisions'] = decisions
    result['uncertain_edges'] = sum(d['status'] == 'unknown' for d in decisions)
    result['iam_evaluated_edges'] = sum(d['status'] in ('potential', 'denied', 'unknown') for d in decisions)
    result['scope'] = 'Conservative offline identity-policy overlay. Unknown edges excluded from confirmed modeled paths; AWS effective authorization not determined.'
    return result


def linked_simulation(environment, policies, disabled_edges):
    before = linked_analysis(environment, policies)
    after = linked_analysis(environment, policies, disabled_edges)
    removed = {f['id'] for f in before['findings']} - {f['id'] for f in after['findings']}
    return {'before': before, 'after': after, 'removed_paths': len(removed), 'remaining_paths': after['total_paths']}
