import asyncio, json, os, re, time
from dataclasses import dataclass
from typing import Any
import httpx

TOOL_NAMES={'get_system_health','find_port_owner','scan_dev_artifacts','propose_cleanup','approve_cleanup','verify_cleanup'}
MODEL_DEFAULTS='gemini-3.8-flash,gemini-3.6-flash,gemini-3.5-flash-lite,gemini-3.1-flash-lite'
@dataclass
class CandidateState:
    disabled: bool=False
    cooldown_until: float=0.0
    failures: int=0
    last_error: str=''

_states: dict[tuple[str,int],CandidateState]={}
_lock=asyncio.Lock()

def keys(): return [x.strip() for x in (os.getenv('GEMINI_API_KEYS') or os.getenv('GEMINI_API_KEY','')).split(',') if x.strip()]
def models(): return [x.strip() for x in (os.getenv('GEMINI_MODELS') or MODEL_DEFAULTS).split(',') if x.strip()]
def rules(message: str) -> dict[str,Any]:
    low=message.lower()
    m=re.search(r'\bport\s+(\d{1,5})\b',low)
    if m: return {'tool':'find_port_owner','args':{'port':int(m.group(1))},'interpreter':'rules'}
    if any(x in low for x in ('cleanup','clean up','free space','propose')): return {'tool':'propose_cleanup','args':{},'interpreter':'rules'}
    if any(x in low for x in ('scan','artifact','node_modules','venv')): return {'tool':'scan_dev_artifacts','args':{},'interpreter':'rules'}
    if any(x in low for x in ('cpu','memory','disk','drive','health','system status')): return {'tool':'get_system_health','args':{},'interpreter':'rules'}
    return {'tool':None,'args':{},'interpreter':'rules'}

def validate(obj):
    if not isinstance(obj,dict) or set(obj)!={'tool','args'}: raise ValueError('invalid response shape')
    tool=obj['tool']; args=obj['args']
    if tool not in {'get_system_health','find_port_owner','scan_dev_artifacts','propose_cleanup'}: raise ValueError('tool is not available to model routing')
    if not isinstance(args,dict): raise ValueError('args must be an object')
    if tool=='find_port_owner':
        if set(args)!={'port'} or type(args['port']) is not int or not 1<=args['port']<=65535: raise ValueError('invalid port arguments')
    elif args: raise ValueError('unexpected tool arguments')
    return {'tool':tool,'args':args}

async def _generate(model,key,message,timeout):
    schema={'type':'OBJECT','properties':{'tool':{'type':['STRING','NULL'],'enum':sorted(TOOL_NAMES)+[None]},'args':{'type':'OBJECT','properties':{'port':{'type':'INTEGER'}},'additionalProperties':False}},'required':['tool','args'],'additionalProperties':False}
    prompt=('Choose one tool for the user request. You only route intent; do not answer with measurements or take actions. '
            'Never approve or deny cleanup. If no supported action matches, output tool null and empty args. '
            'Supported tool names: get_system_health, find_port_owner(port integer 1..65535), scan_dev_artifacts, propose_cleanup. '
            'Do not invent a reference. Return only JSON {"tool":...,"args":...}. User request: '+message)
    url=f'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent'
    payload={'contents':[{'role':'user','parts':[{'text':prompt}]}], 'generationConfig':{'responseMimeType':'application/json','responseSchema':schema,'temperature':0}}
    async with httpx.AsyncClient(timeout=timeout) as client:
        response=await client.post(url,headers={'x-goog-api-key':key},json=payload)
        return response

async def interpret(message: str):
    api_keys=keys(); model_list=models()
    if not api_keys or not model_list: return rules(message)
    try: total=float(os.getenv('GEMINI_TOTAL_BUDGET_SECONDS','8')); timeout=float(os.getenv('GEMINI_TIMEOUT_SECONDS','4')); cap=int(os.getenv('GEMINI_MAX_ATTEMPTS','3'))
    except ValueError: return rules(message)
    deadline=time.monotonic()+max(.1,total); attempts=0
    for model in model_list:
        for ki,key in enumerate(api_keys):
            if attempts>=cap or time.monotonic()>=deadline: break
            candidate=(model,ki)
            async with _lock: state=_states.setdefault(candidate,CandidateState())
            if state.disabled or state.cooldown_until>time.monotonic(): continue
            attempts+=1
            try:
                response=await _generate(model,key,message,min(timeout,max(.1,deadline-time.monotonic())))
                if response.status_code in (401,403,404):
                    async with _lock: state.disabled=True; state.last_error=f'HTTP {response.status_code}'
                    continue
                if response.status_code==429 or response.status_code>=500:
                    async with _lock:
                        state.failures+=1; state.last_error=f'HTTP {response.status_code}'
                        retry=response.headers.get('Retry-After')
                        try: retry_delay=max(1,float(retry)) if retry else 0
                        except ValueError: retry_delay=0
                        delay=min(600 if response.status_code==429 else 300, retry_delay or (60 if response.status_code==429 else 30)*2**(state.failures-1))
                        state.cooldown_until=time.monotonic()+delay
                    continue
                response.raise_for_status()
                body=response.json(); text=body['candidates'][0]['content']['parts'][0]['text']; parsed=validate(json.loads(text))
                async with _lock: state.failures=0; state.cooldown_until=0; state.last_error=''
                return parsed | {'interpreter':f'model:{model}'}
            except (httpx.TimeoutException,httpx.NetworkError):
                async with _lock: state.failures+=1; state.last_error='network/timeout'; state.cooldown_until=time.monotonic()+min(300,30*2**(state.failures-1))
            except (ValueError,KeyError,IndexError,httpx.HTTPStatusError):
                async with _lock: state.failures+=1; state.last_error='invalid response'; state.cooldown_until=time.monotonic()+120 if state.failures>=3 else 0
    return rules(message)

async def status():
    async with _lock:
        return [{'model':m,'key_index':i,'status':'disabled' if s.disabled else ('cooldown' if s.cooldown_until>time.monotonic() else 'ready'),'cooldown_seconds':max(0,int(s.cooldown_until-time.monotonic())),'last_error':s.last_error} for (m,i),s in _states.items()]
