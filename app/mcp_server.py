from mcp.server.mcpserver import MCPServer
import json
from .core import health, port_owner, scan, propose, approve, verify, restore, audit

server = MCPServer("DevDoctor", version="0.1.0", instructions="Local measurements and explicit approval-gated cleanup.")
def _json(data): return json.dumps(data, separators=(',',':'))
def _record(name,args,result):
    result['data']['audit_persisted']=audit(name,args,result['status'],result['spoken'])
    return _json(result)
def get_system_health() -> str: return _record('get_system_health',{},health())
def find_port_owner(port: int) -> str: return _record('find_port_owner',{'port':port},port_owner(port))
def scan_dev_artifacts() -> str: return _record('scan_dev_artifacts',{},scan())
def propose_cleanup() -> str: return _record('propose_cleanup',{},propose())
def approve_cleanup(reference: str, approved: bool) -> str: return _record('approve_cleanup',{'reference':'[redacted]','approved':approved},approve(reference, approved))
def verify_cleanup(reference: str) -> str: return _record('verify_cleanup',{},verify(reference))
def restore_quarantine(reference: str) -> str: return _record('restore_quarantine',{'reference':'[redacted]'},restore(reference))
for fn in (get_system_health, find_port_owner, scan_dev_artifacts, propose_cleanup, approve_cleanup, verify_cleanup, restore_quarantine): server.add_tool(fn)
