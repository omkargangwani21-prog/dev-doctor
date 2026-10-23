import json, os, shutil, sqlite3, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import psutil
from . import settings
from .redact import redact

KINDS = {"node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", ".next", "dist", "build", ".gradle", "target"}
MAX_FILES_PER_ITEM = int(os.getenv("DEVDOCTOR_MAX_FILES_PER_ITEM", "20000"))

def now_iso(): return datetime.now(timezone.utc).isoformat()
def db():
    c=sqlite3.connect(settings.DB_PATH, timeout=10); c.row_factory=sqlite3.Row
    c.execute("CREATE TABLE IF NOT EXISTS audit_events(id INTEGER PRIMARY KEY, ts TEXT, tool TEXT, input_summary TEXT, status TEXT, detail TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS proposals(ref TEXT PRIMARY KEY, ts_created REAL, ts_expires REAL, state TEXT, snapshot_json TEXT, result_json TEXT)")
    c.commit(); return c

def audit(tool, summary, status, detail):
    try:
        c=db(); c.execute("INSERT INTO audit_events(ts,tool,input_summary,status,detail) VALUES(?,?,?,?,?)", (now_iso(),str(redact(tool)),str(redact(summary))[:300],status,str(redact(detail))[:500])); c.commit(); c.close(); return True
    except Exception: return False

def envelope(spoken, data=None, evidence=None, status="success"):
    return {"spoken":spoken,"data":data or {},"evidence":evidence or [],"status":status}

def roots():
    out=[]
    for p in settings.ROOTS:
        try: real=Path(os.path.realpath(p)); st=real.stat(); out.append((real,st))
        except FileNotFoundError: pass
        except OSError: pass
    return out

def is_link_or_junction(path: Path) -> bool:
    try: return path.is_symlink() or (hasattr(os.path,'isjunction') and os.path.isjunction(path))
    except OSError: return True

def inside(path: Path, root: Path) -> bool:
    try: return os.path.normcase(os.path.commonpath([str(path),str(root)])) == os.path.normcase(str(root))
    except ValueError: return False

def item_size(path: Path):
    total=0; newest=0.0; n=0; partial=False
    for base, dirs, files in os.walk(path, followlinks=False):
        dirs[:] = [d for d in dirs if not is_link_or_junction(Path(base)/d)]
        for name in files:
            f=Path(base)/name
            try:
                st=f.stat(follow_symlinks=False); total+=st.st_size; newest=max(newest,st.st_mtime); n+=1
                if n>=MAX_FILES_PER_ITEM: partial=True; return total,newest,partial
            except OSError: partial=True
    try: newest=max(newest,path.stat().st_mtime)
    except OSError: pass
    return total,newest,partial

def allowed_target(p: Path): return p.name != "target" or (p.parent/"Cargo.toml").exists() or (p.parent/"pom.xml").exists()

def scan():
    configured=[Path(p).expanduser() for p in settings.ROOTS]
    if not configured: return envelope("No folders chosen yet.", {"roots":[],"items":[],"totals":{"items":0,"bytes":0},"partial":False,"measured_at":now_iso()}, status="unavailable")
    root_info=[]; found={}; partial=False
    for configured_root in configured:
        if is_link_or_junction(configured_root): root_info.append({"path":str(configured_root),"status":"denied","artifact_dirs":0,"bytes":0}); partial=True; continue
        root=Path(os.path.realpath(configured_root))
        if not root.exists(): root_info.append({"path":str(root),"status":"missing","artifact_dirs":0,"bytes":0}); partial=True; continue
        try:
            if not os.access(root,os.R_OK): raise PermissionError()
            count=0; size=0
            for base,dirs,_ in os.walk(root,followlinks=False):
                dirs[:]=[d for d in dirs if not (Path(base)/d).is_symlink()]
                for d in list(dirs):
                    p=Path(base)/d
                    if d not in KINDS or not allowed_target(p): continue
                    rp=Path(os.path.realpath(p))
                    if not inside(rp,root): continue
                    b,mt,part=item_size(p); partial|=part
                    if str(rp) in found: continue
                    age=max(0,(time.time()-mt)/86400); kind=d
                    try: same=p.stat().st_dev == settings.QUARANTINE.parent.stat().st_dev
                    except OSError: same=False
                    item={"id":uuid.uuid4().hex[:12],"path":str(rp),"kind":kind,"bytes":b,"newest_mtime":datetime.fromtimestamp(mt,timezone.utc).isoformat(),"age_days":round(age,1),"protected_recent":age<settings.RECENT_DAYS,"same_volume_as_quarantine":same,"root":str(root),"partial":part}
                    found[str(rp)]=item; count+=1; size+=b
                    dirs.remove(d)
            root_info.append({"path":str(root),"status":"ok","artifact_dirs":count,"bytes":size})
        except PermissionError: root_info.append({"path":str(root),"status":"denied","artifact_dirs":0,"bytes":0}); partial=True
    items=list(found.values())
    data={"roots":root_info,"items":items,"totals":{"items":len(items),"bytes":sum(x['bytes'] for x in items)},"scan_id":uuid.uuid4().hex,"partial":partial,"measured_at":now_iso()}
    return envelope(f"Measured {len(items)} development artifact folders.",data,[{"source":"filesystem","kind":"scan","value":data["totals"]}],"degraded" if partial else "success")

def health():
    vm=psutil.virtual_memory(); drives=[]
    for part in psutil.disk_partitions(all=False):
        try:
            u=psutil.disk_usage(part.mountpoint); drives.append({"mount":part.mountpoint,"used":u.used,"total":u.total,"percent":u.percent,"over_limit":u.percent>=settings.DISK_LIMIT_PCT})
        except OSError: pass
    return envelope("Measured system health.",{"cpu_percent":psutil.cpu_percent(interval=0.2),"memory":{"used":vm.used,"total":vm.total,"percent":vm.percent},"drives":drives,"disk_limit_percent":settings.DISK_LIMIT_PCT,"measured_at":now_iso()},[{"source":"psutil","kind":"system_health","value":"measured"}])

def port_owner(port):
    if not isinstance(port,int) or not 1<=port<=65535: return envelope("Port must be between 1 and 65535.",{"error":{"category":"invalid_port"}},status="rejected")
    owners=[]; limited=False
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and c.laddr.port==port and c.status==psutil.CONN_LISTEN:
            try:
                p=psutil.Process(c.pid) if c.pid else None
                owners.append({"name":p.name() if p else None,"pid":c.pid,"cmdline":None,"cwd":None,"started_at":datetime.fromtimestamp(p.create_time(),timezone.utc).isoformat() if p else None,"bind_address":c.laddr.ip,"memory_mb":round(p.memory_info().rss/1048576,1) if p else None})
            except (psutil.AccessDenied,psutil.NoSuchProcess): limited=True; owners.append({"name":None,"pid":c.pid,"cmdline":None,"cwd":None,"started_at":None,"bind_address":c.laddr.ip,"memory_mb":None})
    data={"port":port,"listening":bool(owners),"owners":owners,"limited":limited}
    return envelope(f"Port {port} is {'in use' if owners else 'not listening'}; no action taken.",data,[{"source":"psutil","kind":"port_owner","value":port}],"degraded" if limited else "success")

def propose():
    result=scan(); eligible=[x for x in result["data"]["items"] if x["age_days"]>=settings.RECENT_DAYS and not x["protected_recent"]]
    if not eligible: return envelope("Nothing is safe to move right now.",{"proposed":False,"items":[],"total_bytes":0},status="success")
    ref=uuid.uuid4().hex; created=time.time(); c=db(); c.execute("INSERT INTO proposals VALUES(?,?,?,?,?,?)",(ref,created,created+120,"pending",json.dumps(eligible),None)); c.commit(); c.close()
    same=any(x["same_volume_as_quarantine"] for x in eligible)
    return envelope(f"Proposed {len(eligible)} folders. Explicit approval is required.",{"proposed":True,"reference":ref,"expires_at":datetime.fromtimestamp(created+120,timezone.utc).isoformat(),"items":eligible,"total_bytes":sum(x['bytes'] for x in eligible),"same_volume_warning":same,"requires_explicit_approval":True})

def approve(ref,approved):
    c=db(); c.execute('BEGIN IMMEDIATE'); row=c.execute("SELECT * FROM proposals WHERE ref=?",(ref,)).fetchone()
    if not row or row['state']!='pending' or row['ts_expires']<time.time(): c.close(); return envelope("Proposal is unknown, used, or expired.",{"executed":False,"moved":[]},status="rejected")
    if not approved: c.execute("UPDATE proposals SET state='denied' WHERE ref=?",(ref,)); c.commit(); c.close(); return envelope("Proposal denied. Nothing was moved.",{"executed":False,"approval_decision":"denied","moved":[]},status="rejected")
    changed=c.execute("UPDATE proposals SET state='reserved' WHERE ref=? AND state='pending'",(ref,)); c.commit()
    if changed.rowcount!=1: c.close(); return envelope("Proposal is already in use.",{"executed":False,"moved":[]},status="rejected")
    items=json.loads(row['snapshot_json']); moved=[]; skipped=[]; qroot=Path(os.path.realpath(settings.QUARANTINE)); stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+ref[:8]; qdir=qroot/stamp
    volume_before={}
    for x in items:
        mount=Path(x['path']).anchor
        try: volume_before[mount]=shutil.disk_usage(mount).free
        except OSError: pass
    for i,x in enumerate(items):
        original=Path(x['path']); src=Path(os.path.realpath(original)); root=Path(os.path.realpath(x['root']))
        try:
            if original.is_symlink() or (hasattr(os.path,'isjunction') and os.path.isjunction(original)) or src.is_symlink() or not inside(src,root) or src.name not in KINDS or not allowed_target(src): raise ValueError('safety revalidation failed')
            size,mt,_=item_size(src)
            old=datetime.fromisoformat(x['newest_mtime']).timestamp()
            if abs(mt-old)>2 or abs(size-x['bytes'])>max(1,x['bytes']*.05): raise ValueError('item changed since scan')
            qdir.mkdir(parents=True,exist_ok=True)
            if inside(qdir,root): raise ValueError('quarantine is inside scan root')
            target=qdir/f"{i:03d}-{src.name}"; shutil.move(str(src),str(target)); moved.append({"path":str(src),"quarantine_path":str(target),"bytes":size})
        except Exception as exc: skipped.append({"path":x['path'],"reason":str(exc)})
    if moved:
        (qdir/'manifest.json').write_text(json.dumps({"created_at":now_iso(),"items":[{"original_path":m['path'],"quarantine_path":m['quarantine_path'],"bytes":m['bytes']} for m in moved]},indent=2),encoding='utf-8')
    data={"executed":bool(moved),"moved":moved,"skipped":skipped,"bytes_moved":sum(x['bytes'] for x in moved),"quarantine_dir":str(qdir) if moved else None,"volume_before":volume_before}
    c.execute("UPDATE proposals SET state='consumed',result_json=? WHERE ref=?",(json.dumps(data),ref)); c.commit(); c.close()
    return envelope(f"Moved {len(moved)} folders to quarantine; no files were deleted.",data,status="degraded" if skipped else "success")

def verify(ref):
    c=db(); c.execute('BEGIN IMMEDIATE'); row=c.execute("SELECT * FROM proposals WHERE ref=?",(ref,)).fetchone(); c.close()
    if not row or not row['result_json']: return envelope("No completed cleanup is available to verify.",{"verification_status":"inconclusive"},status="unavailable")
    res=json.loads(row['result_json']); before=res.get('volume_before',{}); moved=res['bytes_moved']
    # Compare each source volume with its free-space measurement taken immediately before approval.
    per=[]; same=False; moved_by_mount={}
    for item in res['moved']:
        mount=Path(item['path']).anchor; moved_by_mount[mount]=moved_by_mount.get(mount,0)+item['bytes']
    for mount,b in before.items():
        try:
            a=shutil.disk_usage(mount).free; d=a-b; per.append({"mount":mount,"free_before":b,"free_after":a,"delta":d,"bytes_moved":moved_by_mount.get(mount,0)}); same |= d < moved_by_mount.get(mount,0)*.9
        except OSError: pass
    status='inconclusive' if not per or moved<=0 else ('not_verified' if same else 'verified')
    message="moved, no space freed on this volume" if same else ("No items were moved, so there is nothing to verify." if moved<=0 else "Measured free space after the move.")
    data={"verification_status":status,"bytes_moved":moved,"freed_bytes_measured":sum(max(0,x['delta']) for x in per),"per_volume":per,"same_volume":same,"message":message}
    res['verification_status']=status
    c=db(); c.execute("UPDATE proposals SET result_json=? WHERE ref=?",(json.dumps(res),ref)); c.commit(); c.close()
    return envelope(data['message'],data,status={'verified':'success','not_verified':'degraded','inconclusive':'unavailable'}[status])

def restore(ref):
    """Restore only paths recorded by a completed proposal; never overwrite a destination."""
    c=db(); c.execute('BEGIN IMMEDIATE')
    row=c.execute("SELECT * FROM proposals WHERE ref=?",(ref,)).fetchone()
    if not row or not row['result_json']:
        c.close(); return envelope("No completed quarantine move exists for that reference.",{"restored":False,"items":[]},status="unavailable")
    result=json.loads(row['result_json'])
    if result.get('restore_in_progress'):
        c.close(); return envelope("A restore for this proposal is already in progress.",{"restored":False,"items":[]},status="rejected")
    if not result.get('moved'):
        c.close(); return envelope("This proposal has no quarantined items to restore.",{"restored":False,"items":[]},status="unavailable")
    if len(result.get('restored_paths',[]))>=len(result['moved']):
        c.close(); return envelope("All items from this proposal are already restored.",{"restored":False,"items":result.get('restored_paths',[])},status="rejected")
    result['restore_in_progress']=True
    c.execute("UPDATE proposals SET result_json=? WHERE ref=?",(json.dumps(result),ref)); c.commit(); c.close()

    snapshots={x['path']:x for x in json.loads(row['snapshot_json'])}
    restored=list(result.get('restored_paths',[])); skipped=[]; quarantine=Path(os.path.realpath(settings.QUARANTINE))
    for item in result['moved']:
        original_text=item['path']
        if original_text in restored: continue
        original=Path(original_text); source=Path(item['quarantine_path']); snap=snapshots.get(original_text)
        try:
            if not snap: raise ValueError('original scan record is missing')
            root=Path(os.path.realpath(snap['root']))
            if is_link_or_junction(source) or source.is_symlink(): raise ValueError('quarantined item is a link')
            source_real=Path(os.path.realpath(source))
            if not inside(source_real,quarantine) or not source_real.is_dir(): raise ValueError('quarantined item failed path validation')
            if is_link_or_junction(original.parent): raise ValueError('original parent is a link')
            parent=Path(os.path.realpath(original.parent))
            if not inside(parent,root) or not parent.is_dir(): raise ValueError('original parent is missing or outside its scan root')
            if os.path.lexists(original): raise ValueError('original destination already exists; refusing to overwrite')
            shutil.move(str(source_real),str(original))
            restored.append(original_text)
        except Exception as exc:
            skipped.append({'path':original_text,'reason':str(exc)})
    result['restored_paths']=restored; result['restore_in_progress']=False
    c=db(); c.execute("UPDATE proposals SET result_json=? WHERE ref=?",(json.dumps(result),ref)); c.commit(); c.close()
    done=len(restored)==len(result['moved'])
    data={'restored':bool(restored),'complete':done,'items':restored,'skipped':skipped}
    return envelope(f"Restored {len(restored)} of {len(result['moved'])} quarantined folders." if done else f"Restored {len(restored)} of {len(result['moved'])}; some items need attention.",data,status='success' if done else 'degraded')

def tool_call(name,args):
    if name=='get_system_health': return health()
    if name=='find_port_owner': return port_owner(args.get('port'))
    if name=='scan_dev_artifacts': return scan()
    if name=='propose_cleanup': return propose()
    if name=='approve_cleanup': return approve(args.get('reference',''),bool(args.get('approved',False)))
    if name=='verify_cleanup': return verify(args.get('reference',''))
    if name=='restore_quarantine': return restore(args.get('reference',''))
    return envelope("Unknown tool.",{"error":{"category":"unknown_tool"}},status="rejected")
