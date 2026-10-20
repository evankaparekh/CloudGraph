import json
from pathlib import Path
from backend.linked import evaluate, linked_analysis, linked_simulation

SAMPLE = json.loads((Path(__file__).parents[1] / 'samples' / 'linked-demo.json').read_text())

def test_explicit_deny_overrides_allow():
    policy = {'Statement': [{'Effect':'Allow','Action':'s3:*','Resource':'*'}, {'Effect':'Deny','Action':'s3:GetObject','Resource':'*'}]}
    assert evaluate(policy,'s3:GetObject','arn:aws:s3:::test/file')[0] == 'denied'

def test_no_allow_denied():
    assert evaluate({'Statement': []}, 's3:GetObject','*')[0] == 'denied'

def test_conditions_are_unknown():
    policy={'Statement':[{'Effect':'Allow','Action':'s3:GetObject','Resource':'*','Condition':{'Bool':{'aws:SecureTransport':'true'}}}]}
    assert evaluate(policy,'s3:GetObject','arn:aws:s3:::test/file')[0] == 'unknown'

def test_linked_demo_excludes_denied_edge():
    result=linked_analysis(**SAMPLE)
    assert result['iam_evaluated_edges']==4
    assert result['decisions'][5]['status']=='denied'
    assert result['total_paths'] == 3

def test_linked_simulation_reduces_paths():
    result=linked_simulation(**SAMPLE,disabled_edges=[0])
    assert result['after']['total_paths']==0
    assert result['removed_paths']==3

def test_unknown_does_not_prove_access():
    policies=dict(SAMPLE['policies']);policies.pop('role')
    result=linked_analysis(SAMPLE['environment'],policies)
    assert result['total_paths']==0
    assert result['uncertain_edges']==3
