"""Bounded regressions from independent review; synthetic authority and effects."""
import multiprocessing
import pytest
from pydantic import ValidationError
from tests.test_bounded_authorization import proposal, resolver_for, workflow, NOW, PROFILE, PRINCIPAL
from agent_control_plane.bounded import LocalRefundDestination, DefinitiveDestinationRejection, RuntimeProposal


def test_delegated_grant_is_unsupported_even_with_identity_chain(tmp_path):
    p=proposal();resolver=resolver_for(p,delegated=True)
    flow=workflow(tmp_path,p,resolver=resolver)
    result=flow.decide(p,now=NOW)
    assert result.result=='hold'
    assert 'delegation_profile_unsupported' in result.reasons
    assert not flow.destination.snapshot()['effects']


@pytest.mark.parametrize('state',['unknown','stale'])
def test_explicit_noncurrent_context_holds_when_required(tmp_path,state):
    p=proposal();resolver=resolver_for(p)
    context=resolver.contexts[PROFILE]
    item=next(e for e in context['requirement']['evidence'] if e['kind']!='authorization')
    item['unknown_behavior']='hold_effect'
    resolver.evidence[item['obligation_id']].state=state
    result=workflow(tmp_path,p,resolver=resolver).decide(p,now=NOW)
    assert result.result=='hold'
    assert 'context_unknown_requires_hold' in result.reasons


def test_principal_cannot_supply_independent_approval(tmp_path):
    p=proposal();resolver=resolver_for(p)
    for a in resolver.approvals.values(): a.approver=PRINCIPAL
    result=workflow(tmp_path,p,resolver=resolver).decide(p,now=NOW)
    assert result.result=='hold'
    assert 'approval_independence_violation' in result.reasons


@pytest.mark.parametrize('amount',[float('inf'),float('-inf'),float('nan')])
def test_nonfinite_amount_rejected_at_schema_boundary(amount):
    data=proposal().model_dump();data['amount']=amount
    with pytest.raises(ValidationError):RuntimeProposal(**data)


def spend(path,ready,start,queue,identity):
    destination=LocalRefundDestination(path);ready.put(True);start.wait(5)
    try:
        destination.apply(effect_id=identity,grant_id='shared',max_effects=1,target='synthetic',amount=1,unit='USD',payload={})
        queue.put('acknowledged')
    except DefinitiveDestinationRejection:queue.put('denied')


def test_local_destination_serializes_process_budget_and_keeps_acknowledged_effect(tmp_path):
    ctx=multiprocessing.get_context('spawn');ready=ctx.Queue();queue=ctx.Queue();start=ctx.Event()
    path=tmp_path/'destination.json'
    processes=[ctx.Process(target=spend,args=(path,ready,start,queue,str(i))) for i in range(2)]
    try:
        for p in processes:p.start()
        for _ in processes:ready.get(timeout=10)
        start.set()
        results=sorted(queue.get(timeout=10) for _ in processes)
        assert results==['acknowledged','denied']
        for p in processes:p.join(10);assert p.exitcode==0
        state=LocalRefundDestination(path).snapshot()
        assert len(state['effects'])==1
        assert state['grant_effect_counts']['shared']==1
    finally:
        for p in processes:
            if p.is_alive():p.kill();p.join()
