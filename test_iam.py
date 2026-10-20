import pytest
from backend.iam import inspect_policy


def test_broad_permissions_detected():
    result = inspect_policy({'Statement': {'Effect':'Allow', 'Action':'iam:*', 'Resource':'*'}})
    assert any(f['action'] == 'iam:AttachRolePolicy' for f in result['findings'])


def test_explicit_deny_overrides_same_resource():
    policy = {'Statement': [
        {'Effect':'Allow','Action':'iam:PassRole','Resource':'*'},
        {'Effect':'Deny','Action':'iam:PassRole','Resource':'*'}]}
    assert inspect_policy(policy)['count'] == 0


def test_condition_not_treated_as_unconditional():
    policy = {'Statement': {'Effect':'Allow','Action':'iam:PassRole','Resource':'*','Condition':{'StringEquals':{'aws:RequestedRegion':'us-east-1'}}}}
    result = inspect_policy(policy)
    assert result['count'] == 0
    assert any('Condition' in w for w in result['warnings'])


def test_reject_unsupported_notaction():
    with pytest.raises(ValueError):
        inspect_policy({'Statement': {'Effect':'Allow','NotAction':'s3:*','Action':'*','Resource':'*'}})


def test_read_only_not_flagged():
    assert inspect_policy({'Statement': {'Effect':'Allow','Action':'ec2:DescribeInstances','Resource':'*'}})['count'] == 0
