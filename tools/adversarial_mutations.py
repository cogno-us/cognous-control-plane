"""Require targeted assertions to detect removed authorization controls."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
CASES=[
 ('delegation','reasons.append("delegation_profile_unsupported")','pass','test_delegated_grant_is_unsupported_even_with_identity_chain'),
 ('independence','approval.approver in {proposal.actor, proposal.principal, *identity.chain}','False','test_principal_cannot_supply_independent_approval'),
 ('unknown-context','current is None or current.state != "current" or not self._fresh(','current is None or not self._fresh(','test_explicit_noncurrent_context_holds_when_required'),
]
for name,before,after,test in CASES:
 with tempfile.TemporaryDirectory() as directory:
  tmp=Path(directory);shutil.copytree(ROOT/'src',tmp/'src');shutil.copytree(ROOT/'tests',tmp/'tests')
  p=tmp/'src/agent_control_plane/bounded.py';s=p.read_text()
  if s.count(before)!=1:raise RuntimeError('mutation target drift: '+name)
  p.write_text(s.replace(before,after))
  import os
  env=dict(os.environ,PYTHONPATH=str(tmp/'src'))
  result=subprocess.run([sys.executable,'-m','pytest','-q','tests/test_adversarial_review.py::'+test],cwd=tmp,env=env,capture_output=True,text=True,timeout=30)
  if result.returncode!=1 or 'AssertionError' not in result.stdout or 'ERROR' in result.stdout:
   raise RuntimeError('mutation not killed by assertions: '+name+'\n'+result.stdout+result.stderr)
  print('DETECTED: '+name)
