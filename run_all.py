import argparse, socket, subprocess, sys, time, urllib.request

def free(port):
    with socket.socket() as s:
        try: s.bind(('127.0.0.1',port)); return True
        except OSError: return False

def main():
    parser=argparse.ArgumentParser(description='Run the Dev Doctor local web app and MCP endpoint')
    parser.add_argument('--fresh',action='store_true',help='start with a clean local database')
    args=parser.parse_args()
    if args.fresh:
        from app import settings
        try: __import__('pathlib').Path(settings.DB_PATH).unlink(missing_ok=True)
        except OSError: pass
    from app import settings
    if not free(settings.WEB_PORT): raise SystemExit(f'Web port {settings.WEB_PORT} is busy; no process was stopped.')
    print(f'Dev Doctor ready at http://{settings.WEB_HOST}:{settings.WEB_PORT} (MCP endpoint /mcp)',flush=True)
    import uvicorn
    uvicorn.run('app.web:app',host=settings.WEB_HOST,port=settings.WEB_PORT,reload=False)
if __name__=='__main__': main()
