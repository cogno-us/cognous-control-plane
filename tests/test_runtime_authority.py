"""Original synthetic K1–K5 fixtures derived from supplied 101526_A."""
import multiprocessing
import os
from datetime import timedelta
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from agent_control_plane.bounded import (BoundedAuthorizationWorkflow,BoundedRecordStore,CheckEvent,
    LocalRefundDestination,ObservationPolicy,_canonical_bytes,commitment,_process_owner)
from agent_control_plane.runtime_authority import ActionClass,RuntimeAuthorityProfile,approval_commitment,PurposeStatus
from tests.test_bounded_authorization import NOW,PROFILE,INSTITUTION,manifest,proposal,resolver_for,workflow
KEY=Ed25519PrivateKey.from_private_bytes(bytes(range(32))) # public synthetic fixture only
PUBLIC=KEY.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
MEMBERS=[f'synthetic-file-{i}' for i in range(40)]
def sign_evidence(status,*,members=None,count=40,tenant_id=None):
    statement={'version':'validation-record/0.1','producer_id':'synthetic-validator',
        'obligation_id':status.obligation_id,'subject_digest':commitment(MEMBERS),
        'observed_at':status.observed_at,'institution_id':INSTITUTION,
        'authority_domain':'customer-refunds','tenant_id':tenant_id,
        'values':{'validated_count':count,'validated_members':MEMBERS if members is None else members}}
    status.validation_record={'statement':statement,'signature':KEY.sign(_canonical_bytes(statement)).hex()}
def bind_approval(r,cfg):
    for a in r.approvals.values():a.runtime_authority_commitment=approval_commitment(cfg,r.contexts[PROFILE])
def setup_flow(tmp_path,*,purpose=False,reversible=False,kind='exact_members'):
    p=proposal();r=resolver_for(p)
    cl=ActionClass(class_id='synthetic-reversible' if reversible else 'synthetic-irreversible',
        irreversible=not reversible,max_status_age_seconds=60,
        on_unreadable='bounded_tolerance' if reversible else 'refuse')
    cfg=RuntimeAuthorityProfile(catalogue_version='synthetic-catalogue/1',actions={p.action_id:cl},
        producer_keys={'synthetic-validator':PUBLIC},allow_synthetic_resolver=True)
    base=workflow(tmp_path/'baseline',p,resolver=r).decide(p,now=NOW)
    required=sorted([{'input_type':x.input_type,'input_id':x.input_id} for x in base.resolution_inputs],key=lambda x:(x['input_type'],x['input_id']))
    context=r.contexts[PROFILE];criteria={}
    for ob in context['requirement']['evidence']:
        if ob['required'] and ob['kind']=='authorization':
            criteria[ob['obligation_id']]={'kind':kind,'producer_id':'synthetic-validator',
                'subject_digest':commitment(MEMBERS),'minimum_count':40,'members':MEMBERS}
            sign_evidence(r.evidence[ob['obligation_id']])
    context['runtime_authority']={'profile':'runtime-authority/0.1','required_inputs':required,
        'required_inputs_digest':commitment(required),'evidence_criteria':criteria}
    if purpose:
        context['grant']['purpose_ref']={'system':'synthetic-cases','record_id':'case-1','epoch':'epoch-1'}
        r.purpose=PurposeStatus(system='synthetic-cases',record_id='case-1',epoch='epoch-1',
            institution_id=INSTITUTION,authority_domain='customer-refunds',state='open',
            observed_at=NOW.isoformat(),epoch_capability='authoritative')
        r.purpose_status=lambda ref:r.purpose.model_dump()
    bind_approval(r,cfg)
    f=BoundedAuthorizationWorkflow(manifest=manifest(),resolver=r,destination=LocalRefundDestination(tmp_path/'destination.json'),
        records=BoundedRecordStore(tmp_path/'run.json','run-1'),observation_policy=ObservationPolicy(max_age_seconds=300),
        allow_test_time=True,runtime_authority_profile=cfg)
    return p,r,f,cfg
def held(f,p,reason):
    d=f.decide(p,now=NOW);assert d.result=='hold' and reason in d.reasons,d.reasons
    assert f.destination.snapshot()['effects']=={} and not f.records.load().attempts
    return d
def test_profile_positive_and_vocabulary(tmp_path,monkeypatch):
    import agent_control_plane.bounded as bounded
    monkeypatch.setattr(bounded,'_now',lambda:NOW)
    p,r,f,c=setup_flow(tmp_path);d=f.decide(p,now=NOW);assert d.result=='authorized',d.reasons
    assert d.reason_vocabulary_version=='runtime-authority-reasons/0.1'
    a,o=f.execute(p,d,adapter_id=p.adapter_id,now=NOW);assert a.status=='acknowledged' and o.state=='applied'
    events=f.records.load().check_events
    assert [x.phase for x in events].count('opened')==[x.phase for x in events].count('completed')==2
    assert all(x.owner and x.proposal_commitment for x in events)
def test_resolver_returns_none_distinct_code(tmp_path):
    p,r,f,c=setup_flow(tmp_path);r.grant_status=lambda ref:None;d=held(f,p,'status_unreadable')
    assert 'grant_revoked' not in d.reasons and d.reopen_conditions==[{'kind':'readable_authority_status'}]
def test_resolver_raises_refusal_recorded(tmp_path):
    p,r,f,c=setup_flow(tmp_path);d=f.decide(p,now=NOW)
    def broken(ref):raise TimeoutError('PRIVATE_FAILURE_DETAIL')
    r.grant_status=broken
    with pytest.raises(PermissionError):f.execute(p,d,adapter_id=p.adapter_id,now=NOW)
    row=f.records.load().refusals[0];assert row.reasons==['status_unreadable']
    assert any(x.input_type=='mandate' for x in row.resolution_inputs)
    assert any(x.input_type=='grant' and x.missing and x.read_state=='unreadable' for x in row.resolution_inputs)
    assert 'PRIVATE_FAILURE_DETAIL' not in f.records.path.read_text()
    assert not f.records.load().attempts and f.destination.snapshot()['effects']=={}
def _die_mid_read(root):
    p,r,f,c=setup_flow(root);r.grant_status=lambda ref:os._exit(71);f.decide(p,now=NOW)
def test_process_dies_mid_resolve_reads_interrupted(tmp_path):
    proc=multiprocessing.get_context('fork').Process(target=_die_mid_read,args=(tmp_path,));proc.start();proc.join(10)
    assert proc.exitcode==71
    records=BoundedRecordStore(tmp_path/'run.json','run-1');assert records.recover_interrupted_checks()==1
    assert records.recover_interrupted_checks()==0
    row=records.load();assert row.check_events[-1].phase=='interrupted' and row.check_events[-1].reasons==['check_interrupted']
    assert not row.decisions and not row.attempts
    assert any(e.input and e.input.input_type=='mandate' for e in row.check_events)
def test_live_owner_cannot_be_recovered(tmp_path):
    p,r,f,c=setup_flow(tmp_path)
    f.records.append_check_event(CheckEvent(check_id='live',phase='opened',stage='effect',recorded_at=NOW.isoformat(),owner=_process_owner(),proposal_commitment=commitment({})))
    with f.records.check_lease('live'):
        assert f.records.recover_interrupted_checks()==0
@pytest.mark.parametrize('reversible,cache,age,expected',[(False,True,1,'hold'),(True,True,1,'authorized'),(True,False,1,'hold'),(True,True,61,'hold')])
def test_irreversible_class_refuses_on_unreadable_reversible_tolerates_bounded_age(tmp_path,reversible,cache,age,expected):
    p,r,f,c=setup_flow(tmp_path,reversible=reversible);status=next(iter(r.statuses.values())).model_copy(deep=True)
    status.observed_at=(NOW-timedelta(seconds=age)).isoformat();r.grant_status=lambda ref:None;r.cached_grant_status=lambda ref:status if cache else None
    d=f.decide(p,now=NOW);assert d.result==expected,d.reasons
    if expected=='authorized':assert any(x.read_state=='cached_positive' for x in d.resolution_inputs)
    assert f.destination.snapshot()['effects']=={}
def test_known_denial_overrides_cache(tmp_path):
    p,r,f,c=setup_flow(tmp_path,reversible=True);old=next(iter(r.statuses.values())).model_copy(deep=True)
    next(iter(r.statuses.values())).status='revoked';r.cached_grant_status=lambda ref:old;held(f,p,'grant_revoked')
def test_holder_cannot_reclassify_action(tmp_path):
    p,r,f,c=setup_flow(tmp_path);r.contexts[PROFILE]['grant']['action_class']='reversible';r.grant_status=lambda ref:None
    held(f,p,'status_unreadable');assert f.records.load().check_events[0].action_class['irreversible']
def test_revoked_code_requires_snapshot(tmp_path):
    p,r,f,c=setup_flow(tmp_path);next(iter(r.statuses.values())).status='revoked';d=held(f,p,'grant_revoked')
    assert any(x.observed.get('status')=='revoked' and x.record_commitment for x in d.resolution_inputs)
    assert d.reopen_conditions[0]['kind']=='successor_grant_revision'
@pytest.mark.parametrize('stage',['opened','input','completed'])
def test_journal_write_failure_never_dispatches(tmp_path,monkeypatch,stage):
    p,r,f,c=setup_flow(tmp_path);original=f.records.append_check_event
    def write(event):
        if event.phase==stage:raise OSError('synthetic journal failure')
        original(event)
    monkeypatch.setattr(f.records,'append_check_event',write)
    with pytest.raises(OSError):f.decide(p,now=NOW)
    assert not f.records.load().decisions and f.destination.snapshot()['effects']=={}
def test_evidence_count_below_criterion_holds(tmp_path):
    p,r,f,c=setup_flow(tmp_path,kind='minimum_count');sign_evidence(next(iter(r.evidence.values())),count=5);held(f,p,'evidence_criterion_unmet')
@pytest.mark.parametrize('members',[MEMBERS[:37]+['unapproved-a','unapproved-b','unapproved-c'],MEMBERS[:39]+[MEMBERS[0]]])
def test_evidence_set_outside_approved_manifest_holds(tmp_path,members):
    p,r,f,c=setup_flow(tmp_path);sign_evidence(next(iter(r.evidence.values())),members=members);held(f,p,'evidence_criterion_unmet')
def test_agent_rewritten_validator_record_holds(tmp_path):
    p,r,f,c=setup_flow(tmp_path);next(iter(r.evidence.values())).validation_record['statement']['values']['validated_count']=999;held(f,p,'evidence_signature_invalid')
@pytest.mark.parametrize('case,reason',[('unsigned','evidence_unsigned'),('producer','evidence_producer_untrusted'),('subject','evidence_subject_mismatch'),('criterion','evidence_criterion_unsupported')])
def test_evidence_negative_contracts(tmp_path,case,reason):
    p,r,f,c=setup_flow(tmp_path);e=next(iter(r.evidence.values()))
    if case=='unsigned':e.validation_record=None
    elif case=='producer':e.validation_record['statement']['producer_id']='agent'
    elif case=='subject':sign_evidence(e,tenant_id='different-tenant')
    else:
        next(iter(r.contexts[PROFILE]['runtime_authority']['evidence_criteria'].values()))['version']='unknown';bind_approval(r,c)
    held(f,p,reason)
def test_input_dropped_from_list_holds(tmp_path):
    p,r,f,c=setup_flow(tmp_path);required=r.contexts[PROFILE]['runtime_authority']['required_inputs']
    required.append({'input_type':'evidence','input_id':'required-but-not-read'});required.sort(key=lambda x:(x['input_type'],x['input_id']))
    r.contexts[PROFILE]['runtime_authority']['required_inputs_digest']=commitment(required);bind_approval(r,c);held(f,p,'required_input_not_read')
def test_planner_cannot_change_approved_input_set(tmp_path):
    p,r,f,c=setup_flow(tmp_path);r.contexts[PROFILE]['runtime_authority']['required_inputs']=[];held(f,p,'runtime_authority_approval_mismatch')
def test_grant_bound_to_closed_case_holds(tmp_path):
    p,r,f,c=setup_flow(tmp_path,purpose=True);r.purpose.state='closed';held(f,p,'purpose_closed')
def test_reopened_case_does_not_revive_grant(tmp_path):
    p,r,f,c=setup_flow(tmp_path,purpose=True);r.purpose.epoch='epoch-2';held(f,p,'purpose_epoch_changed')
def test_purpose_source_unreachable_irreversible_refuses(tmp_path):
    p,r,f,c=setup_flow(tmp_path,purpose=True)
    def unavailable(ref):raise TimeoutError()
    r.purpose_status=unavailable;held(f,p,'purpose_unreadable')
def test_status_only_purpose_cannot_claim_epoch_protection(tmp_path):
    p,r,f,c=setup_flow(tmp_path,purpose=True);r.purpose.epoch_capability='status_only';held(f,p,'purpose_epoch_capability_unsupported')
def test_expiryless_legacy_grant_fails_closed(tmp_path):
    p,r,f,c=setup_flow(tmp_path);del r.contexts[PROFILE]['grant']['expires_at'];bind_approval(r,c);held(f,p,'grant_expiry_required')
def test_refusal_row_carries_vocabulary_version(tmp_path):
    p,r,f,c=setup_flow(tmp_path);d=f.decide(p,now=NOW);next(iter(r.statuses.values())).status='revoked'
    with pytest.raises(PermissionError):f.execute(p,d,adapter_id=p.adapter_id,now=NOW)
    assert f.records.load().refusals[0].reason_vocabulary_version=='runtime-authority-reasons/0.1'
def test_required_profile_cannot_be_downgraded_at_execute(tmp_path):
    p,r,f,c=setup_flow(tmp_path);d=f.decide(p,now=NOW);legacy=workflow(tmp_path/'legacy',p,resolver=r);legacy.records=f.records;legacy.destination=f.destination
    with pytest.raises(PermissionError):legacy.execute(p,d,adapter_id=p.adapter_id,now=NOW)
    assert f.destination.snapshot()['effects']=={}

def test_code_split_produces_vocabulary_change_row(tmp_path):
    from agent_control_plane.reason_vocabulary import VocabularyChange
    p,r,f,c=setup_flow(tmp_path);d=f.decide(p,now=NOW)
    next(iter(r.statuses.values())).status='revoked'
    with pytest.raises(PermissionError):f.execute(p,d,adapter_id=p.adapter_id,now=NOW)
    old=f.records.load().refusals[0].model_dump()
    event=VocabularyChange(change_id='synthetic-split',previous_version='runtime-authority-reasons/0.1',
        version='synthetic-reasons/0.2',registry_digest=commitment({'synthetic':True}),kind='split',
        previous_codes=['old'],codes=['new_a','new_b'],acknowledged_by='synthetic-owner',acknowledged_at=NOW.isoformat())
    f.records.append_vocabulary_change(event)
    assert f.records.load().vocabulary_changes==[event]
    assert f.records.load().refusals[0].model_dump()==old
    with pytest.raises(ValueError):f.records.append_vocabulary_change(event)

def test_reason_disappearance_requires_exposure_and_keeps_unknown_versions():
    from agent_control_plane.reason_vocabulary import refusal_trends
    prior=[{'reason_vocabulary_version':'v1','reasons':['old']}] * 5
    report=refusal_trends(prior,[{'reasons':['other']}],previous_exposure=10,current_exposure=10)
    assert report['total_refusals']==1 and report['unversioned_rows']==1
    assert any(x['code']=='old' and x['disappeared'] and x['share']==0 for x in report['series'])
    assert not any(x['disappeared'] for x in refusal_trends(prior,[],previous_exposure=10,current_exposure=0)['series'])

def test_recorded_denial_cannot_be_overridden_by_later_outage_cache(tmp_path):
    p,r,f,c=setup_flow(tmp_path,reversible=True)
    cached=next(iter(r.statuses.values())).model_copy(deep=True)
    next(iter(r.statuses.values())).status='revoked'
    held(f,p,'grant_revoked')
    r.grant_status=lambda ref:None;r.cached_grant_status=lambda ref:cached
    held(f,p,'status_unreadable')


# ---------------------------------------------------------------------------
# Reason registry completeness (csf_b8d4416255cdcf1f3ed44095)
# ---------------------------------------------------------------------------
import ast
import json
import typing
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_REASON_SOURCES = ("bounded.py", "runtime_authority.py")
_REASON_NAMES = {"reasons", "mismatches", "result", "refusal_reasons"}
# Non-literal values that are known to carry reasons produced elsewhere in the
# scanned sources (and therefore already enumerated by this walk).
_DELEGATED = {"extra_reasons", "validate_evidence(status, criterion, profile, context)",
              "defects"}  # defects: age-extension defect codes from freshness.extension_defects (checked by tests/test_freshness.py)


def _reason_literals(node, grant_states):
    """Yield (code, lineno) for a reason-carrying expression; fail on unknown shapes."""
    if isinstance(node, (ast.List, ast.Tuple)):
        for item in node.elts:
            yield from _reason_literals(item, grant_states)
    elif isinstance(node, ast.Constant) and isinstance(node.value, str):
        yield node.value, node.lineno
    elif isinstance(node, ast.IfExp):
        yield from _reason_literals(node.body, grant_states)
        yield from _reason_literals(node.orelse, grant_states)
    elif (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)
          and isinstance(node.left, ast.Constant) and node.left.value == "grant_"
          and ast.unparse(node.right) == "status.status"):
        for state in grant_states:
            if state != "active":
                yield "grant_" + state, node.lineno
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        if not (isinstance(node.left, ast.Name) and node.left.id in _REASON_NAMES):
            yield from _reason_literals(node.left, grant_states)
        yield from _reason_literals(node.right, grant_states)
    elif isinstance(node, ast.JoinedStr):
        prefix = node.values[0]
        assert isinstance(prefix, ast.Constant) and prefix.value.endswith(":"), ast.unparse(node)
        yield prefix.value[:-1], node.lineno
    elif isinstance(node, ast.Call) and ast.unparse(node.func) in {"sorted", "set", "list"}:
        for arg in node.args:
            yield from _reason_literals(arg, grant_states)
    elif ast.unparse(node) in _DELEGATED or (isinstance(node, ast.Name) and node.id in _REASON_NAMES):
        return
    else:
        raise AssertionError(f"unrecognised reason expression at line {node.lineno}: {ast.unparse(node)}")


def _emitted_reason_codes():
    from agent_control_plane.bounded import GrantStatus
    grant_states = typing.get_args(GrantStatus.model_fields["status"].annotation)
    assert grant_states
    found = {}
    for name in _REASON_SOURCES:
        tree = ast.parse((_REPO / "src" / "agent_control_plane" / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            values = []
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in {"append", "extend"}
                    and isinstance(node.func.value, ast.Name) and node.func.value.id in _REASON_NAMES):
                values = list(node.args)
            elif isinstance(node, ast.Call):
                values = [k.value for k in node.keywords if k.arg == "reasons"]
            elif isinstance(node, ast.Assign):
                targets = [n.id for t in node.targets for n in ast.walk(t) if isinstance(n, ast.Name)]
                if set(targets) & _REASON_NAMES:
                    value = node.value
                    if isinstance(value, ast.Tuple) and len(targets) == 2:
                        value = value.elts[0]
                    if isinstance(value, (ast.List, ast.BinOp)) or (
                            isinstance(value, ast.Call) and ast.unparse(value.func) == "sorted"):
                        values = [value]
            elif isinstance(node, ast.Return) and node.value is not None:
                # Reason-returning helpers return either sorted(...) or a
                # (reasons, binding/extension) tuple whose first item is a list.
                value = node.value.elts[0] if isinstance(node.value, ast.Tuple) and node.value.elts else node.value
                if isinstance(value, ast.List) or (
                        isinstance(value, ast.Call) and ast.unparse(value.func) == "sorted"):
                    values = [value]
            elif isinstance(node, ast.FunctionDef) and node.name == "validate_evidence":
                values = [r.value for r in ast.walk(node)
                          if isinstance(r, ast.Return) and isinstance(r.value, ast.List)]
            for value in values:
                for code, line in _reason_literals(value, grant_states):
                    found.setdefault(code, f"{name}:{line}")
    return found


def test_every_emitted_reason_code_is_in_the_versioned_registry():
    registry = json.loads((_REPO / "schemas" / "runtime_authority_reasons_0_1.json").read_text(encoding="utf-8"))
    assert registry["version"] == "runtime-authority-reasons/0.1"
    emitted = _emitted_reason_codes()
    # Guard the walk itself: representative codes from every emission shape.
    for sample in ("adapter_mismatch", "authority_context_missing", "grant_suspended",
                   "check_interrupted", "authorization_binding_changed", "evidence_unsigned",
                   "observation_unavailable", "input_observation_time_regressed",
                   "tenant_proposal_required", "purpose_closed", "status_unreadable"):
        assert sample in emitted, sample
    missing = {code: where for code, where in emitted.items() if code not in registry["codes"]}
    assert not missing, f"emitted reason codes absent from registry: {missing}"
