# Dev Doctor

Dev Doctor is a local developer-machine assistant for safe, reversible cleanup. It measures system health, checks listening ports, and scans only folders you choose. When it finds supported development artifacts, it creates an exact proposal and waits for your approval. Approved folders move to quarantine, can be verified, and can be restored. Dev Doctor never deletes files or stops processes.

## Features

- Live CPU, memory, and disk measurements, with a drive selector.
- Read-only lookup for listening ports and process owners when the OS permits access.
- User-selected scan roots and an allowlist of known artifact folders.
- Protection for recently changed artifacts.
- Expiring, single-use cleanup proposals with explicit approval or denial.
- Quarantine with a manifest, post-action measurement, restore, and a local audit trail.
- Seven MCP tools served over Streamable HTTP.

## Run on Windows

Requires Python 3.12 or newer.

```powershell
Set-Location D:\DevDoctor
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python run_all.py
```

Open <http://127.0.0.1:8002>. On the Disk page, choose a folder or enter its full path, add it as a scan root, then scan. Only configured roots are scanned. The MCP endpoint is available at `/mcp` on the same local server.

## Run on macOS or Linux

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
python run_all.py
```

Then open <http://127.0.0.1:8002>.

## Safety

A scan does not move anything. Cleanup requires approval of a specific proposal, which expires after two minutes and is revalidated before action. Approved artifacts are moved to quarantine, never deleted. Restore refuses to overwrite a folder recreated at the original path. A move on the same drive may not free disk space; the app reports measured results.

Keep quarantine outside all scan roots. Avoid scanning broad system folders. Local settings, roots, database files, virtual environments, caches, and demo fixtures are excluded from Git.

## Alexa+ and Gemini

The browser interface is a **simulated Alexa+ client**. It is not connected to an Alexa device or official Alexa+ tools. Optional Gemini intent routing is available when configured; otherwise, Dev Doctor uses deterministic rules. Live Gemini calls were not tested for this build.

## Stack

Python, FastAPI, MCP Python SDK, Streamable HTTP, SQLite, psutil, HTML, CSS, and JavaScript.
