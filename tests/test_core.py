import json, os, time
from pathlib import Path
from app import core, settings
from app.interpreter.chain import rules, validate

def make_tree(root: Path, kind='node_modules', age_days=30):
    p=root/'project'/kind; p.mkdir(parents=True); f=p/'package.txt'; f.write_text('sample')
    past=time.time()-age_days*86400; os.utime(f,(past,past)); os.utime(p,(past,past)); os.utime(p.parent,(past,past)); return p

def configure(monkeypatch,tmp_path,root):
    monkeypatch.setattr(settings,'ROOTS',[root]); monkeypatch.setattr(settings,'QUARANTINE',tmp_path/'quarantine'); monkeypatch.setattr(settings,'DB_PATH',str(tmp_path/'audit.sqlite'))

def test_rules_route_port_and_cleanup_without_approval():
    assert rules('Why is port 8000 busy?')['args']=={'port':8000}
    assert rules('clean up what is safe')['tool']=='propose_cleanup'
    assert rules('ok')['tool'] is None
    assert rules('approve it')['tool'] is None

def test_model_response_validation_rejects_approval_and_bad_args():
    assert validate({'tool':'find_port_owner','args':{'port':443}})['tool']=='find_port_owner'
    for value in [
        {'tool':'approve_cleanup','args':{'reference':'abc','approved':True}},
        {'tool':'find_port_owner','args':{'port':70000}},
        {'tool':'scan_dev_artifacts','args':{'path':'C:/'}},
        {'tool':'unknown','args':{}},
    ]:
        try: validate(value)
        except ValueError: pass
        else: raise AssertionError(f'accepted unsafe model output: {value}')

def test_scan_protects_recent_and_lists_old(monkeypatch,tmp_path):
    root=tmp_path/'root'; root.mkdir(); old=make_tree(root,'node_modules',30); recent=make_tree(root,'venv',1)
    configure(monkeypatch,tmp_path,root)
    data=core.scan()['data']; by_kind={x['kind']:x for x in data['items']}
    assert by_kind['node_modules']['protected_recent'] is False
    assert by_kind['venv']['protected_recent'] is True

def test_proposal_approval_moves_only_to_quarantine_with_manifest(monkeypatch,tmp_path):
    root=tmp_path/'root'; root.mkdir(); artifact=make_tree(root,'node_modules',30); configure(monkeypatch,tmp_path,root)
    proposal=core.propose()['data']; assert proposal['proposed'] is True
    result=core.approve(proposal['reference'],True)['data']
    assert result['executed'] is True and not artifact.exists()
    q=Path(result['moved'][0]['quarantine_path']); assert q.exists()
    manifest=Path(result['quarantine_dir'])/'manifest.json'
    assert json.loads(manifest.read_text())['items'][0]['original_path']==str(artifact)
    reused=core.approve(proposal['reference'],True)
    assert reused['status']=='rejected'

def test_expired_proposal_rejected(monkeypatch,tmp_path):
    root=tmp_path/'root'; root.mkdir(); artifact=make_tree(root,'dist',30); configure(monkeypatch,tmp_path,root)
    proposal=core.propose()['data'];
    import sqlite3
    c=sqlite3.connect(settings.DB_PATH); c.execute('UPDATE proposals SET ts_expires=? WHERE ref=?',(time.time()-1,proposal['reference'])); c.commit(); c.close()
    result=core.approve(proposal['reference'],True)
    assert result['status']=='rejected' and artifact.exists()

def test_audit_redacts_secret_values(monkeypatch,tmp_path):
    monkeypatch.setattr(settings,'DB_PATH',str(tmp_path/'audit.sqlite'))
    assert core.audit('test',{'token':'abc','message':'Bearer secret'},'success','AIza'+'A'*30)
    import sqlite3
    row=sqlite3.connect(settings.DB_PATH).execute('select input_summary,detail from audit_events').fetchone()
    assert 'abc' not in row[0] and 'secret' not in row[0] and 'AIza' not in row[1]
import asyncio
from app.interpreter import chain

class FakeResponse:
    def __init__(self,status,body=None,headers=None): self.status_code=status; self._body=body or {}; self.headers=headers or {}
    def json(self): return self._body
    def raise_for_status(self):
        if self.status_code>=400: raise chain.httpx.HTTPStatusError('bad response',request=None,response=None)

def test_model_failover_keeps_message_as_only_user_data(monkeypatch):
    monkeypatch.setattr(chain,'keys',lambda:['test-key'])
    monkeypatch.setattr(chain,'models',lambda:['first-model','second-model'])
    monkeypatch.setenv('GEMINI_MAX_ATTEMPTS','3'); monkeypatch.setenv('GEMINI_TOTAL_BUDGET_SECONDS','8')
    calls=[]
    async def fake_generate(model,key,message,timeout):
        calls.append((model,key,message))
        if model=='first-model': return FakeResponse(429,headers={'Retry-After':'1'})
        return FakeResponse(200,{'candidates':[{'content':{'parts':[{'text':'{"tool":"find_port_owner","args":{"port":8080}}'}]}}]})
    monkeypatch.setattr(chain,'_generate',fake_generate)
    result=asyncio.run(chain.interpret('Why is port 8080 busy?'))
    assert result=={'tool':'find_port_owner','args':{'port':8080},'interpreter':'model:second-model'}
    assert [x[0] for x in calls]==['first-model','second-model']
    assert all(x[2]=='Why is port 8080 busy?' for x in calls)
from concurrent.futures import ThreadPoolExecutor

def test_concurrent_approvals_execute_at_most_once(monkeypatch,tmp_path):
    root=tmp_path/'root'; root.mkdir(); artifact=make_tree(root,'build',30); configure(monkeypatch,tmp_path,root)
    ref=core.propose()['data']['reference']
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _:core.approve(ref,True),range(2)))
    assert sum(bool(r['data'].get('moved')) for r in results)==1
    assert sum(r['status']=='rejected' for r in results)==1
    assert not artifact.exists()

def test_quarantine_inside_root_is_refused(monkeypatch,tmp_path):
    root=tmp_path/'root'; root.mkdir(); artifact=make_tree(root,'build',30)
    monkeypatch.setattr(settings,'ROOTS',[root]); monkeypatch.setattr(settings,'QUARANTINE',root/'quarantine'); monkeypatch.setattr(settings,'DB_PATH',str(tmp_path/'audit.sqlite'))
    ref=core.propose()['data']['reference']; result=core.approve(ref,True)
    assert artifact.exists()
    assert result['data']['moved']==[]
    assert result['data']['skipped'][0]['reason']=='quarantine is inside scan root'

def test_restore_returns_quarantined_item_and_refuses_overwrite(monkeypatch,tmp_path):
    root=tmp_path/'root'; root.mkdir(); artifact=make_tree(root,'node_modules',30); configure(monkeypatch,tmp_path,root)
    proposal=core.propose()['data']; moved=core.approve(proposal['reference'],True)['data']['moved'][0]
    restored=core.restore(proposal['reference'])
    assert restored['status']=='success' and artifact.exists()
    assert not Path(moved['quarantine_path']).exists()
    assert core.restore(proposal['reference'])['status']=='rejected'

def test_restore_never_overwrites_a_recreated_original(monkeypatch,tmp_path):
    root=tmp_path/'root'; root.mkdir(); artifact=make_tree(root,'build',30); configure(monkeypatch,tmp_path,root)
    proposal=core.propose()['data']; moved=core.approve(proposal['reference'],True)['data']['moved'][0]
    artifact.mkdir(); (artifact/'keep.txt').write_text('do not overwrite')
    result=core.restore(proposal['reference'])
    assert result['status']=='degraded' and 'already exists' in result['data']['skipped'][0]['reason']
    assert (artifact/'keep.txt').read_text()=='do not overwrite'
    assert Path(moved['quarantine_path']).exists()
def test_gemini_defaults_work_when_optional_env_values_are_blank(monkeypatch):
    monkeypatch.setenv('GEMINI_API_KEYS',''); monkeypatch.setenv('GEMINI_API_KEY','test-key')
    monkeypatch.setenv('GEMINI_MODELS','')
    assert chain.keys()==['test-key']
    assert chain.models()==chain.MODEL_DEFAULTS.split(',')
