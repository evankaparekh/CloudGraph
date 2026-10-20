"""Conservative, offline IAM identity-policy inspection; NOT AWS authorization simulation."""
import fnmatch
import json

RISKY_ACTIONS = {
    'iam:CreatePolicyVersion': ('high', 'Can create a new managed policy version; impact depends on attachment and default-version changes.'),
    'iam:SetDefaultPolicyVersion': ('high', 'Can change the active managed policy version.'),
    'iam:AttachUserPolicy': ('high', 'Can attach a managed policy to a user.'),
    'iam:AttachRolePolicy': ('high', 'Can attach a managed policy to a role.'),
    'iam:PutUserPolicy': ('high', 'Can modify an inline user policy.'),
    'iam:PutRolePolicy': ('high', 'Can modify an inline role policy.'),
    'iam:PassRole': ('medium', 'Can pass roles to supported services; exploitability depends on other permissions and trust.'),
    'sts:AssumeRole': ('medium', 'Can request role assumption; the target trust policy must also allow it.'),
    'secretsmanager:GetSecretValue': ('medium', 'Can request secret values where other authorization controls permit.'),
    's3:GetObject': ('medium', 'Can read objects where other authorization controls permit.'),
}

def _items(value, field):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
        return value
    raise ValueError(f'{field} must be a string or nonempty list of strings')

def inspect_policy(policy):
    if not isinstance(policy, dict):
        raise ValueError('IAM policy must be a JSON object')
    statements = policy.get('Statement')
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements or len(statements) > 100:
        raise ValueError('Statement must be an object or list of 1–100 statements')
    normalized = []
    warnings = ['Identity policies alone cannot establish effective AWS permissions: SCPs, boundaries, session policies, resource policies, trust policies and context are not evaluated.']
    for i, s in enumerate(statements):
        if not isinstance(s, dict) or s.get('Effect') not in ('Allow', 'Deny'):
            raise ValueError(f'Statement {i} requires Effect Allow or Deny')
        if 'Action' not in s or 'Resource' not in s:
            raise ValueError(f'Statement {i} requires Action and Resource')
        if 'NotAction' in s or 'NotResource' in s:
            raise ValueError('NotAction and NotResource are not supported; refusing to approximate')
        actions = _items(s['Action'], 'Action')
        resources = _items(s['Resource'], 'Resource')
        if 'Principal' in s or 'NotPrincipal' in s:
            raise ValueError('Only identity-based policies are supported; Principal is not allowed')
        if 'Condition' in s:
            warnings.append(f'Statement {i} contains Condition: it is excluded from definitive matches and requires manual review.')
        normalized.append({'effect': s['Effect'], 'actions': actions, 'resources': resources, 'conditional': 'Condition' in s, 'index': i})
    findings = []
    for action, (severity, explanation) in RISKY_ACTIONS.items():
        for allow in normalized:
            if allow['effect'] != 'Allow' or not any(fnmatch.fnmatchcase(action.lower(), p.lower()) for p in allow['actions']):
                continue
            if allow['conditional']:
                continue
            for resource in allow['resources']:
                # This checks only explicit matching resource strings. It does not imply AWS evaluates all these actions at resource scope.
                denied = any(d['effect'] == 'Deny' and not d['conditional'] and
                    any(fnmatch.fnmatchcase(action.lower(), p.lower()) for p in d['actions']) and
                    any(fnmatch.fnmatchcase(resource, p) for p in d['resources']) for d in normalized)
                if denied:
                    continue
                findings.append({'action': action, 'resource': resource, 'severity': severity,
                    'statement_index': allow['index'], 'reason': explanation,
                    'recommendation': 'Review business need; scope actions and resources to least privilege, and validate using AWS IAM policy simulation and organizational controls.',
                    'confidence': 'potential', 'note': 'Pattern-based indicator only; not a verified effective permission or exploit path.'})
    findings = sorted(findings, key=lambda f: (f['severity'] != 'high', f['action'], f['resource']))[:200]
    return {'findings': findings, 'count': len(findings), 'warnings': list(dict.fromkeys(warnings)),
            'scope': 'Offline identity-policy pattern inspection; no AWS account access or policy execution.'}
