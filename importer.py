"""Offline importer for a documented, intentionally narrow AWS inventory export.

Input is NOT raw AWS Config, CloudFormation or Terraform. Never needs credentials.
Graph edges express hypotheses; IAM Allow does not prove effective authorization.
"""
from .engine import validate_environment

MAX_ITEMS = 100

def _items(payload, name):
    value = payload.get(name, [])
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        raise ValueError(f'{name} must be a list with at most {MAX_ITEMS} entries')
    return value

def _string(obj, key):
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ValueError(f'{key} must be a nonempty string (max 256 characters)')
    return value

def import_inventory(payload):
    if not isinstance(payload, dict) or payload.get('format') != 'cloudgraph-aws-inventory-v1':
        raise ValueError('Expected format: cloudgraph-aws-inventory-v1')
    nodes = [{'id': 'internet', 'label': 'Public Internet', 'kind': 'internet'}]
    edges, policies, warnings = [], {}, []
    ids = {'internet'}
    def add(prefix, name, kind, sensitive=False):
        node_id = prefix + ':' + name
        if node_id in ids:
            raise ValueError('Duplicate resource: ' + node_id)
        ids.add(node_id)
        nodes.append({'id': node_id, 'label': name, 'kind': kind, 'sensitive': sensitive})
        return node_id
    roles = {}
    for role in _items(payload, 'roles'):
        if not isinstance(role, dict): raise ValueError('Each role must be an object')
        name = _string(role, 'name')
        policy = role.get('policy', {'Version':'2012-10-17','Statement':[]})
        if not isinstance(policy, dict): raise ValueError('Role policy must be an object')
        node_id = add('role', name, 'role')
        roles[name] = node_id
        policies[node_id] = policy
        if 'trust_policy' in role:
            warnings.append(f'{name}: trust policies are not evaluated')
    for instance in _items(payload, 'instances'):
        if not isinstance(instance, dict): raise ValueError('Each instance must be an object')
        name = _string(instance, 'id')
        node_id = add('ec2', name, 'compute')
        role_name = instance.get('role')
        if role_name is not None:
            if role_name not in roles: raise ValueError(f'Unknown instance role: {role_name}')
            edges.append({'source':node_id,'target':roles[role_name],'permission':'assume-role', 'note':'Assumed attached instance role; trust and instance profile not evaluated'})
        ingress = instance.get('ingress', [])
        if not isinstance(ingress, list): raise ValueError('Instance ingress must be a list')
        if instance.get('public_ip') is True and any(isinstance(rule,dict) and rule.get('cidr') in ('0.0.0.0/0','::/0') and rule.get('port') in (80,443) for rule in ingress):
            edges.append({'source':'internet','target':node_id,'permission':'reachable','note':'Possible public HTTP(S) exposure; network controls not fully evaluated'})
        elif instance.get('public_ip') is True:
            warnings.append(f'{name}: public IP present but no supported public HTTP(S) ingress identified')
    resources = []
    for key, prefix, kind, action in [('buckets','s3','bucket','s3:GetObject'),('databases','rds','database','rds-db:connect'),('secrets','secret','secret','secretsmanager:GetSecretValue')]:
        for resource in _items(payload, key):
            if not isinstance(resource, dict): raise ValueError(f'Each {key} entry must be an object')
            name = _string(resource, 'name')
            arn = _string(resource, 'arn')
            node_id = add(prefix, name, kind, resource.get('sensitive', True) is True)
            resources.append((node_id, arn, action))
            if kind == 'bucket' and resource.get('public') is True:
                warnings.append(f'{name}: marked public; S3 policy and block-public-access controls not evaluated')
    # Edges are generated only for actions matching the supplied identity policy.
    # The IAM-linked analyzer will filter Deny/unknown decisions; other AWS controls remain unknown.
    from .linked import evaluate
    for role_id, policy in policies.items():
        for resource_id, arn, action in resources:
            decision, _ = evaluate(policy, action, arn)
            if decision == 'potential':
                edges.append({'source':role_id,'target':resource_id,'permission':'read','iam_action':action,'iam_resource':arn})
            elif decision == 'unknown':
                warnings.append(f'{role_id} → {resource_id}: policy decision unknown; omitted from graph')
    environment = {'name':payload.get('name','Imported AWS inventory (offline)'), 'nodes':nodes,'edges':edges}
    validate_environment(environment)
    warnings.append('Modeled relationships are hypotheses, not verified AWS effective access or exploitation paths.')
    return {'environment':environment,'policies':policies,'warnings':warnings,'counts':{'roles':len(roles),'resources':len(resources),'instances':len(_items(payload,'instances'))}}
