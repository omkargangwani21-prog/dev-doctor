from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from contextlib import asynccontextmanager
import json, re
from .core import tool_call, health, port_owner, scan, propose, approve, verify, audit, db
from . import settings
from .mcp_server import server as mcp_server
from .interpreter import interpret, status as interpreter_status
from mcp.server.transport_security import TransportSecuritySettings
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

@asynccontextmanager
async def lifespan(app):
    c=db(); c.close()
    async with mcp_server.session_manager.run():
        yield

app=FastAPI(title="Dev Doctor",version="0.1.0",lifespan=lifespan)
@app.middleware('http')
async def protect_remote_bind(request:Request, call_next):
    import hmac
    remote=settings.WEB_HOST not in ('127.0.0.1','localhost','::1')
    if remote:
        if len(settings.ADMIN_TOKEN)<32: return JSONResponse({'detail':'A 32-character DEVDOCTOR_ADMIN_TOKEN is required for non-loopback binds.'},status_code=403)
        supplied=request.headers.get('authorization','')
        if not hmac.compare_digest(supplied, 'Bearer '+settings.ADMIN_TOKEN): return JSONResponse({'detail':'Unauthorized'},status_code=401)
    return await call_next(request)

app.mount('/static',StaticFiles(directory=Path(__file__).parent/'static'),name='static')
app.mount('/mcp', mcp_server.streamable_http_app(streamable_http_path='/', host=settings.MCP_HOST, transport_security=TransportSecuritySettings(allowed_hosts=[settings.WEB_HOST, f'{settings.WEB_HOST}:{settings.WEB_PORT}', 'localhost', f'localhost:{settings.WEB_PORT}', '127.0.0.1', f'127.0.0.1:{settings.WEB_PORT}'])))

async def mcp_call(name: str, arguments: dict | None = None):
    host='[::1]' if settings.WEB_HOST=='::1' else settings.WEB_HOST
    url=f'http://{host}:{settings.WEB_PORT}/mcp/'
    async with streamable_http_client(url) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result=await session.call_tool(name, arguments or {})
            for block in result.content:
                if getattr(block, 'type', None)=='text':
                    try: return json.loads(block.text)
                    except (ValueError, TypeError): pass
    raise RuntimeError(f'MCP tool {name} returned no JSON envelope')
TOOLS=[{"name":"get_system_health","description":"Measure CPU, memory and drives","inputSchema":{"type":"object","properties":{},"additionalProperties":False}},{"name":"find_port_owner","description":"Read-only lookup for a listening port","inputSchema":{"type":"object","properties":{"port":{"type":"integer","minimum":1,"maximum":65535}},"required":["port"],"additionalProperties":False}},{"name":"scan_dev_artifacts","description":"Scan configured roots for known development artifacts","inputSchema":{"type":"object","properties":{},"additionalProperties":False}},{"name":"propose_cleanup","description":"Create an expiring cleanup proposal; moves nothing","inputSchema":{"type":"object","properties":{},"additionalProperties":False}},{"name":"approve_cleanup","description":"Approve or deny a pending cleanup reference","inputSchema":{"type":"object","properties":{"reference":{"type":"string"},"approved":{"type":"boolean"}},"required":["reference","approved"],"additionalProperties":False}},{"name":"verify_cleanup","description":"Measure free space after cleanup","inputSchema":{"type":"object","properties":{"reference":{"type":"string"}},"required":["reference"],"additionalProperties":False}},{"name":"restore_quarantine","description":"Restore a completed proposal from quarantine without overwriting existing files","inputSchema":{"type":"object","properties":{"reference":{"type":"string"}},"required":["reference"],"additionalProperties":False}}]
@app.get('/',response_class=HTMLResponse)
@app.get('/{page}',response_class=HTMLResponse)
async def index(page:str=''):
    return (Path(__file__).parent/'static'/'index.html').read_text(encoding='utf-8')
@app.get('/api/health')
async def api_health(): return await mcp_call('get_system_health')
@app.get('/api/scan')
async def api_scan(): return await mcp_call('scan_dev_artifacts')
@app.get('/api/roots')
async def api_roots(): return {"roots":[str(p) for p in settings.ROOTS]}
@app.post('/api/roots/pick')
def api_pick_root():
    try:
        import tkinter as tk
        from tkinter import filedialog
        window=tk.Tk(); window.withdraw(); window.attributes('-topmost', True)
        selected=filedialog.askdirectory(parent=window,title='Choose a Dev Doctor scan root',mustexist=True)
        window.destroy()
        if not selected: return {"cancelled":True,"roots":[str(p) for p in settings.ROOTS]}
        return add_root(selected)
    except Exception as exc:
        return JSONResponse({"error":f"Native folder picker unavailable: {type(exc).__name__}. Enter the folder path instead.","roots":[str(p) for p in settings.ROOTS]},status_code=501)
@app.post('/api/roots')
async def api_add_root(req:Request):
    body=await req.json(); return add_root(str(body.get('path','')))
def add_root(value:str):
    import os
    raw=Path(value).expanduser()
    if not value.strip(): return JSONResponse({"error":"Choose or enter a folder path."},status_code=400)
    if raw.is_symlink() or (hasattr(os.path,'isjunction') and os.path.isjunction(raw)):
        return JSONResponse({"error":"Symbolic links and junctions cannot be scan roots."},status_code=400)
    try: real=Path(os.path.realpath(raw)); real.stat()
    except OSError: return JSONResponse({"error":"That folder does not exist or cannot be accessed."},status_code=400)
    if not real.is_dir(): return JSONResponse({"error":"Choose a folder, not a file."},status_code=400)
    if not os.access(real,os.R_OK): return JSONResponse({"error":"That folder is not readable."},status_code=400)
    if real in settings.ROOTS: return {"roots":[str(p) for p in settings.ROOTS],"added":False}
    settings.ROOTS.append(real)
    try: settings.save_roots()
    except OSError:
        settings.ROOTS.remove(real)
        return JSONResponse({"error":"Could not save roots to the local project folder."},status_code=500)
    return {"roots":[str(p) for p in settings.ROOTS],"added":True}
@app.delete('/api/roots')
async def api_remove_root(req:Request):
    body=await req.json(); target=str(body.get('path',''))
    for root in list(settings.ROOTS):
        if str(root)==target:
            settings.ROOTS.remove(root)
            try: settings.save_roots()
            except OSError:
                settings.ROOTS.append(root)
                return JSONResponse({"error":"Could not save roots to the local project folder."},status_code=500)
            return {"roots":[str(p) for p in settings.ROOTS],"removed":True}
    return JSONResponse({"error":"That folder is not in the configured scan roots."},status_code=404)
@app.get('/api/proposals')
async def api_proposals(req:Request):
    import sqlite3, time
    c=sqlite3.connect(settings.DB_PATH); c.row_factory=sqlite3.Row
    row=c.execute("SELECT * FROM proposals WHERE state='pending' ORDER BY ts_created DESC LIMIT 1").fetchone(); c.close()
    pending=None
    if row and row['ts_expires']>time.time():
        items=json.loads(row['snapshot_json']); dt=__import__('datetime').datetime; pending={"reference":row['ref'],"expires_at":dt.fromtimestamp(row['ts_expires'],dt.timezone.utc).isoformat(),"items":items,"total_bytes":sum(x['bytes'] for x in items),"same_volume_warning":any(x.get('same_volume_as_quarantine') for x in items)}
    c=sqlite3.connect(settings.DB_PATH); c.row_factory=sqlite3.Row
    completed=c.execute("SELECT ref,result_json FROM proposals WHERE state='consumed' AND result_json IS NOT NULL ORDER BY ts_created DESC LIMIT 1").fetchone(); c.close()
    last=None
    if completed:
        result=json.loads(completed['result_json']); moved=result.get('moved',[]); restored=result.get('restored_paths',[])
        last={"reference":completed['ref'],"moved":moved,"restored_paths":restored,"verification":result.get('verification_status'),"restore_available":bool(moved and len(restored)<len(moved))}
    return {"pending":pending,"completed":last,"recent_days":settings.RECENT_DAYS}
@app.post('/api/proposals')
async def api_propose(req:Request):
    result=await mcp_call('propose_cleanup'); return result['data'] | {"spoken":result['spoken']}
@app.post('/api/approve')
async def api_approve(req:Request):
    body=await req.json(); return await mcp_call('approve_cleanup',{'reference':str(body.get('reference','')),'approved':bool(body.get('approved'))})
@app.post('/api/verify')
async def api_verify(req:Request):
    body=await req.json(); return await mcp_call('verify_cleanup',{'reference':str(body.get('reference',''))})
@app.post('/api/restore')
async def api_restore(req:Request):
    body=await req.json(); return await mcp_call('restore_quarantine',{'reference':str(body.get('reference',''))})

@app.get('/api/audit')
def api_audit():
    try:
        import sqlite3
        c=sqlite3.connect(settings.DB_PATH); c.row_factory=sqlite3.Row
        rows=[dict(x) for x in c.execute('SELECT * FROM audit_events ORDER BY id DESC LIMIT 200')]; c.close(); return rows
    except Exception: return []
@app.get('/api/mcp/info')
async def mcp_info(req:Request):
    async with streamable_http_client(f"http://{'[::1]' if settings.WEB_HOST=='::1' else settings.WEB_HOST}:{settings.WEB_PORT}/mcp/") as (read_stream,write_stream):
        async with ClientSession(read_stream,write_stream) as session:
            initialized=await session.initialize(); listed=await session.list_tools()
            return {"transport":"Streamable HTTP","endpoint":"/mcp","protocol":initialized.protocol_version,"tools":[t.name for t in listed.tools],"last_handshake":__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()}
@app.get('/api/interpreter/status')
async def api_interpreter_status(): return await interpreter_status()
@app.post('/api/chat')
async def chat(req:Request):
    body=await req.json(); message=str(body.get('message',''))[:2000]
    intent=await interpret(message); name,args=intent['tool'],intent['args']
    if not name:
        return {"reply":"I can measure system health, look up a port, scan configured folders, or propose safe cleanup. Use the Proposals page to approve or deny a specific proposal.","interpreter":intent['interpreter'],"result":None}
    if name=='verify_cleanup':
        return {"reply":"Open Proposals to verify a completed cleanup; I cannot infer a proposal reference.","interpreter":intent['interpreter'],"result":None}
    result=await mcp_call(name,args)
    return {"reply":result['spoken'],"interpreter":intent['interpreter'],"tool":name,"result":result}
