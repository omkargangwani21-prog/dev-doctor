import os
import json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc

WEB_HOST = os.getenv("DEVDOCTOR_WEB_HOST", "127.0.0.1")
WEB_PORT = env_int("DEVDOCTOR_WEB_PORT", 8002)
MCP_HOST = os.getenv("DEVDOCTOR_MCP_HOST", "127.0.0.1")
MCP_PORT = env_int("DEVDOCTOR_MCP_PORT", 8000)
ROOTS_FILE = Path(os.getenv("DEVDOCTOR_ROOTS_FILE", str(Path(__file__).resolve().parent.parent / ".devdoctor-roots.json")))
ROOTS = [Path(x.strip()).expanduser() for x in os.getenv("DEVDOCTOR_ROOTS", "").split(os.pathsep) if x.strip()]
try:
    saved_roots = json.loads(ROOTS_FILE.read_text(encoding="utf-8"))
    if isinstance(saved_roots, list):
        ROOTS = [Path(x).expanduser() for x in saved_roots if isinstance(x, str) and x.strip()]
except (OSError, ValueError):
    pass
ROOTS = list(dict.fromkeys(ROOTS))
RECENT_DAYS = max(1, env_int("DEVDOCTOR_RECENT_DAYS", 14))
DISK_LIMIT_PCT = min(100, max(1, env_int("DEVDOCTOR_DISK_LIMIT_PCT", 90)))
DB_PATH = os.getenv("DEVDOCTOR_DB_PATH", "devdoctor.db")
QUARANTINE = Path(os.getenv("DEVDOCTOR_QUARANTINE", str(Path.cwd() / "quarantine"))).expanduser()
ADMIN_TOKEN = os.getenv("DEVDOCTOR_ADMIN_TOKEN", "")

def save_roots() -> None:
    ROOTS_FILE.write_text(json.dumps([str(p) for p in ROOTS], indent=2), encoding="utf-8")

if WEB_HOST not in ('127.0.0.1', 'localhost', '::1'):
    raise ValueError('This build only supports loopback binds; set DEVDOCTOR_WEB_HOST=127.0.0.1')
