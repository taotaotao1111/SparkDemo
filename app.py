"""Cowork fastapi-only scaffold — minimal hello + /health.

按 Cowork Guard 子应用规范开发：
  - 用 Decrypted-Userinfo header 拿用户身份（_parse_sso_user）
  - 持久化用 db.properties + psycopg[binary] (PostgreSQL)
  - /health 返 JSON 给 health.sh 探测
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse


def _load_db_properties(path: str = "db.properties") -> dict[str, str]:
    p = Path(__file__).resolve().parent / path
    if not p.exists():
        return {}
    out: dict[str, str] = {}
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _parse_sso_user(decrypted_userinfo: Optional[str]) -> Optional[dict]:
    """从 Decrypted-Userinfo header 解 SSO 用户（latin-1 → JSON 两步）。

    生产环境上 Cowork Guard 网关会注入 header；header 值是被 HTTP 层用 latin-1
    解码过的 UTF-8 字节，必须重编码后才能 json.loads。

    本地 dev 调试时 header 缺失，不走任何环境变量 bypass，请用浏览器插件
    （ModHeader / Header Editor）手动注入一段 mock JSON。安全规范不允许
    “生产跳 SSO”类后门（precheck 会拦）。
    """
    if not decrypted_userinfo:
        return None
    try:
        fixed = decrypted_userinfo.encode("latin-1").decode("utf-8")
        data = json.loads(fixed)
    except Exception:
        return None
    return {
        "email": data.get("email") or data.get("workEmail"),
        "name": data.get("userNameAlias") or data.get("displayName") or data.get("name"),
        "avatar": data.get("thumbAvatar") or data.get("avatar") or "",
        "userId": data.get("userId") or data.get("id"),
        "raw": data,
    }


def _require_user(decrypted_userinfo: Optional[str]) -> dict:
    """拿不到用户 → 401，Cowork Guard 会自动跳 SSO 登录页。所有业务路由 MUST 调。"""
    user = _parse_sso_user(decrypted_userinfo)
    if not user:
        raise HTTPException(status_code=401, detail="unauthenticated")
    return user


# Shared investigations: platform SSO and per-user official CLI authorization.
import argparse
import concurrent.futures
import datetime as dt
import hashlib
import re
import secrets
import signal
import subprocess
import threading
import shutil
import time
from urllib.parse import parse_qs, urlsplit, urlunsplit, urlencode
from zoneinfo import ZoneInfo
from fastapi import Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, ConfigDict
from scripts.collect_evidence import Collector, TRACE, sanitize_text
import case_store
import trace_agent

ROOT = Path(__file__).resolve().parent
WEB = ROOT / 'web'
LEGACY_AUTH_EMAIL = os.environ.get('APP_OPERATOR_EMAIL', 'taojiaxin@xiaohongshu.com').strip().lower()
APM = ROOT / 'runtime' / 'apm' / 'node_modules' / '@xhs' / 'apm-cli' / 'bin' / 'apm-cli.js'
XRAY = ROOT / 'runtime' / 'bin' / 'xray-cli'
ZONE = ZoneInfo('Asia/Shanghai')
POOL = concurrent.futures.ThreadPoolExecutor(max_workers=8)
CLI_LOCKS = {}
STATE_LOCK = threading.RLock()
JOBS = {}
TICKETS = {}
AUTH = {}
MAX_JOBS = 32
QUERY_TTL = 900
AUTH_TTL = 180
app = FastAPI(title='迹线 Trace — 异常证据助手')


def identity(request):
    user = _require_user(request.headers.get('decrypted-userinfo'))
    email = str(user.get('email') or '').strip().lower()
    if not email:
        raise HTTPException(401, 'SSO 未返回可核对的邮箱身份。')
    return email


def signed_in(request, mutation=False):
    actor = identity(request)
    if mutation and request.headers.get('x-trace-request') != '1':
        raise HTTPException(403, '缺少同源请求标记。')
    return actor


@app.middleware('http')
async def guard(request, call_next):
    if request.url.path != '/health':
        try:
            identity(request)
        except HTTPException as e:
            return JSONResponse({'detail':e.detail}, status_code=e.status_code)
    response = await call_next(request)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


def actor_ref(actor):
    return hashlib.sha256(actor.encode()).hexdigest()


def cli_lock(actor):
    with STATE_LOCK:
        return CLI_LOCKS.setdefault(actor,threading.RLock())


def process_env(actor=None):
    env = os.environ.copy()
    # Never inherit a shared API token. The official CLIs own their login files.
    env.pop('APM_TOKEN', None)
    env.pop('XRAY_TOKEN', None)
    key=actor_ref(actor or 'unbound')
    env['APM_CLI_CONFIG_DIR'] = '/tmp/trace-apm-operator-auth' if actor==LEGACY_AUTH_EMAIL else '/tmp/trace-auth/'+key+'/apm'
    env['TRACE_XRAY_PROFILE']=key
    env['TRACE_XRAY_LEGACY_PROFILE']=actor_ref(LEGACY_AUTH_EMAIL)
    env['APM_CLI_SOURCE'] = 'trace-evidence'
    env['TZ'] = 'Asia/Shanghai'
    return env


def tool_path(tool):
    path = APM if tool == 'apm' else ROOT/'scripts'/'xray_profile.py'
    if not path.is_file():
        raise RuntimeError('查询工具未就绪，请检查部署依赖。')
    path.chmod(path.stat().st_mode | 0o100)
    return str(path)


def cli_status(tool,actor):
    cmd = [tool_path(tool)] + (['status','--output','json'] if tool == 'apm' else ['--output-format','json','auth','status'])
    try:
        p = subprocess.run(cmd, env=process_env(actor), capture_output=True, text=True, timeout=20)
        j = json.loads(p.stdout); d = j.get('data',j)
        email = str(d.get('email') or '').strip().lower()
        logged = bool(d.get('loggedIn',d.get('logged_in',False)))
        expired = bool(d.get('refresh_expired',d.get('expired',False))) if tool == 'xray' else False
        return {'connected':p.returncode==0 and logged and not expired and email==actor, 'accountMatches':email==actor if logged else None}
    except Exception:
        return {'connected':False,'accountMatches':None}


def verify_connections(actor):
    states={tool:cli_status(tool,actor) for tool in ['apm','xray']}
    if not all(s['connected'] for s in states.values()):
        raise RuntimeError('请先在连接面板完成 APM 和 XRAY 官方授权，并使用当前 SSO 账号。')
    return states


def prune():
    now=time.time()
    with STATE_LOCK:
        for k,j in list(JOBS.items()):
            if now-j['createdAt']>QUERY_TTL and j['state'] not in ['queued','running']:JOBS.pop(k,None)
        for k,t in list(TICKETS.items()):
            if now-t['createdAt']>300:TICKETS.pop(k,None)


def create_job(actor, work, *, verify=True):
    prune()
    with STATE_LOCK:
        if len([j for j in JOBS.values() if j['owner']==actor and j['state'] in ['queued','running']])>=2:
            raise HTTPException(429,'已有查询正在执行，请等待完成后再试。')
        if len(JOBS)>=MAX_JOBS:
            oldest=next((k for k,j in JOBS.items() if j['state'] in ['complete','error']),None)
            if oldest:JOBS.pop(oldest)
            else:raise HTTPException(429,'查询队列已满。')
        jid=secrets.token_hex(16)
        JOBS[jid]={'id':jid,'owner':actor,'createdAt':time.time(),'state':'queued','steps':[]}
    def run():
        job=JOBS[jid]
        try:
            with cli_lock(actor):
                job['state']='running'
                if verify:verify_connections(actor)
                def progress(title):job['steps'].append({'title':title,'at':dt.datetime.now(ZONE).isoformat(timespec='seconds')})
                job['result']=work(progress)
                job['state']='complete'
        except Exception as e:
            msg=str(e)
            job['error']=msg[:600] if not re.search(r'(?:apmc_|Bearer\s|access_token|refresh_token)',msg,re.I) else '授权或查询失败，请重新连接后重试。'
            job['state']='error'
        finally:job['elapsedSeconds']=round(time.time()-job['createdAt'],2)
    POOL.submit(run)
    return {'jobId':jid}


def public_job(j):
    return {k:j[k] for k in ['id','state','steps','result','error','elapsedSeconds'] if k in j}


class SearchBody(BaseModel):
    model_config=ConfigDict(extra='forbid')
    sample:str=Field(min_length=1,max_length=600000)
    question:str=Field(default='',max_length=6000)
    occurredAt:Optional[str]=Field(default=None,min_length=10,max_length=50)


class InvestigateBody(BaseModel):
    model_config=ConfigDict(extra='forbid')
    selectionToken:str=Field(pattern=r'^[a-f0-9]{32}$')


def parse_search(body):
    sample=body.sample.strip()
    # Unsupported APM pages must not silently fall through to the timeout workflow.
    for link in re.findall(r'https://tracker\.devops\.xiaohongshu\.com/apm/[^\s<>]+',sample):
        if urlsplit(link).path=='/apm/white-screen-monitor':
            raise HTTPException(422,'当前仅支持 circles 接口超时调查，尚未接入白屏排查流程。请提供要核对的接口 Trace 或超时监控链接。')
    trace=sample.lower() if TRACE.fullmatch(sample.lower()) else None
    app_name='circles'
    if not trace and not sample.startswith('https://'):
        traces={x.lower() for x in re.findall(r'(?<![0-9a-fA-F])(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{16})(?![0-9a-fA-F])',sample)}
        if len(traces)==1:trace=next(iter(traces)).lower()
        elif len(traces)>1:raise HTTPException(422,'线索中包含多个 Trace ID，请一次选择一个要调查的请求。')
        else:
            links=re.findall(r'https://tracker\.devops\.xiaohongshu\.com/apm/[^\s<>]+',sample)
            if len(links)==1:sample=links[0]
    if not trace:
        u=urlsplit(sample)
        if u.scheme!='https' or u.hostname!='tracker.devops.xiaohongshu.com' or not u.path.startswith('/apm/'):
            raise HTTPException(422,'当前仅支持 circles 接口超时调查。请提供 Trace ID、APM 超时监控链接，或包含 Trace 的日志；纯问题尚不能自动定位。')
        params=parse_qs(u.query)
        if params.get('applicationName',['circles'])[0]!='circles':
            raise HTTPException(422,'首版仅支持 circles 应用。')
        candidate=(params.get('traceId') or params.get('trace_id') or [''])[0].lower()
        if candidate and TRACE.fullmatch(candidate):trace=candidate
    if not body.occurredAt:
        return app_name,trace,None
    try:
        anchor=dt.datetime.fromisoformat(body.occurredAt.replace('Z','+00:00'))
        anchor=anchor.replace(tzinfo=ZONE) if not anchor.tzinfo else anchor.astimezone(ZONE)
    except ValueError:raise HTTPException(422,'请提供有效的异常发生时间（北京时间）。')
    if anchor>dt.datetime.now(ZONE)+dt.timedelta(minutes=10):raise HTTPException(422,'异常时间不能晚于当前时间。')
    return app_name,trace,anchor


def search_windows(trace, anchor, now=None):
    """Use a known timestamp only as a locator; every result is queried afresh."""
    now=now or dt.datetime.now(ZONE)
    if anchor:
        return [(anchor-dt.timedelta(minutes=5),anchor+dt.timedelta(minutes=5))], 'manual', '按指定发生时间前后 5 分钟查询'
    if trace:
        path=WEB/'assets'/'evidence.js'
        if not path.is_file():path=ROOT/'assets'/'evidence.js'
        # Only our bundled, sanitized case index is trusted as a timestamp hint.
        text=path.read_text() if path.is_file() else ''
        match=re.search(r'window\.TraceEvidenceCases\s*=\s*(\[.*\])\s*;?\s*$',text,re.S)
        if match:
            cases=json.loads(match.group(1))
            for case in cases:
                incident=case.get('data',{}).get('incident',{})
                if incident.get('traceId')==trace and isinstance(incident.get('timestamp'),(int,float)):
                    anchor=dt.datetime.fromtimestamp(incident['timestamp']/1000,ZONE)
                    hint=(anchor-dt.timedelta(minutes=5),anchor+dt.timedelta(minutes=5))
                    recent=[(now-dt.timedelta(days=i+1),now-dt.timedelta(days=i)) for i in range(7)]
                    return [hint]+recent, 'known-sample-time', '先用已采集样本时间实时复查；未命中再检索最近 7 天，不复用历史结果'
        return [(now-dt.timedelta(days=i+1),now-dt.timedelta(days=i)) for i in range(7)], 'recent-seven-days', '按 Trace ID 从近到远检索最近 7 天，命中后停止；不代表全历史检索'
    return [(now-dt.timedelta(days=1),now)], 'recent-day', '汇总链接未指定发生时间，查询最近 24 小时；可在高级选项缩小范围'


def clean_source(sample):
    if not sample.startswith('https://tracker.devops.xiaohongshu.com/apm/'):return ''
    u=urlsplit(sample);q=parse_qs(u.query)
    safe={k:v for k,v in q.items() if k in ['applicationName','startTime','endTime','errorMessage','timeType']}
    return urlunsplit((u.scheme,u.netloc,u.path,urlencode(safe,doseq=True),''))


def search_work(actor, body, progress):
    app_name,trace,anchor=parse_search(body)
    windows,mode,description=search_windows(trace,anchor)
    args=argparse.Namespace(app=app_name)
    collector=Collector(args,apm=tool_path('apm'),xray=tool_path('xray'))
    collector.process_env=process_env(actor);collector.on_progress=progress
    progress(description)
    searched=[];rows=[]
    for index,(start,end) in enumerate(windows):
        st=str(int(start.timestamp()*1000));et=str(int(end.timestamp()*1000))
        cmd=['log','search','--app',app_name,'--measurement-name','httpRequestTiming','--st',st,'--et',et,'--limit','10']
        if trace:cmd+=['--filter','measurement_data.traceId='+trace]
        else:cmd+=['--filter','measurement_data.errorType=HTTPClientError','--filter','measurement_data.errorMsg~%timeout of 5000ms exceeded%']
        data,audit=collector.query('apm',cmd,f'定位异常 HTTP 样本 · 窗口 {index+1}/{len(windows)}',{'app':app_name,'start':st,'end':et,'traceId':trace,'limit':10})
        logs=data.get('logs') or []
        audit['normalizedTimeRange']=data.get('timeRange');audit['returnedCount']=len(logs);audit['coveredFullRange']=data.get('coveredFullRange');audit['possiblyTruncated']=len(logs)>=10
        searched.append({'start':start.isoformat(),'end':end.isoformat(),'returnedCount':len(logs),'queryId':audit['id']})
        rows=[row for row in logs if TRACE.fullmatch(str((row.get('data') or {}).get('traceId') or '')) and (not trace or row['data']['traceId']==trace) and row.get('userId') and isinstance(row.get('timestamp'),(int,float))]
        if rows:break
    resolution={'mode':mode,'description':description,'searchedWindows':searched,'matchedAt':rows[0].get('time') if len(rows)==1 else None}
    candidates=[]
    for row in rows:
        p=row.get('data') or {};t=p.get('traceId') or ''
        if not TRACE.fullmatch(t) or (trace and t!=trace):continue
        if not row.get('userId'):continue
        token=secrets.token_hex(16)
        with STATE_LOCK:TICKETS[token]={'owner':actor,'createdAt':time.time(),'row':row,'audits':list(collector.audit),'timeResolution':resolution,'question':body.question,'source':clean_source(body.sample)}
        candidates.append({'selectionToken':token,'traceId':t,'time':row.get('time'),'platform':row.get('platform'),'bundle':row.get('artifactVersion'),'error':sanitize_text(str(p.get('errorMsg') or ''))[:300],'status':p.get('status')})
    return {'candidates':candidates,'query':audit,'queries':collector.audit,'timeResolution':resolution,'possiblyTruncated':any(q.get('possiblyTruncated') for q in collector.audit),'coveredFullRange':data.get('coveredFullRange'),'message':'在上述查询窗口中未找到可关联的 HTTP 样本；可在高级选项指定发生时间，并核对平台保留期。' if not candidates else '请选择实际要排查的一次请求；候选不会被自动合并。'}


def investigate_work(ticket, progress, cookie=''):
    actor=ticket['owner']
    row=ticket['row'];raw=row['data'];ts=dt.datetime.fromtimestamp(row['timestamp']/1000,ZONE)
    args=argparse.Namespace(app='circles',user_id=row['userId'],session_id=row.get('sessionId') or None,st=str(int((ts-dt.timedelta(seconds=30)).timestamp()*1000)),et=str(int((ts+dt.timedelta(seconds=30)).timestamp()*1000)),trace_id=raw['traceId'],control_trace=None,control_st=None,control_et=None)
    collector=Collector(args,apm=tool_path('apm'),xray=tool_path('xray'))
    collector.process_env=process_env(actor);collector.on_progress=progress
    collector.audit=list(ticket['audits'])
    case=collector.build()[0]
    case['key']='live-'+secrets.token_hex(6);case['label']='在线采集 · '+str(row.get('time'))
    case['caption']='本次官方 CLI 实际执行结果'
    case['data']['provenance']='real-query'
    case['data']['collection']['semantics']='由发起人的个人授权执行官方 CLI 查询；脱敏案件在工作空间共享，原始授权和进行中的任务不共享。'
    if ticket['source']:case['data']['collection']['sourceUrl']=ticket['source']
    case['data']['collection']['queryCount']=len(collector.audit)
    case['data']['collection']['timeResolution']=ticket['timeResolution']
    case['data']['investigation']={'question':ticket.get('question') or '调查这次客户端超时的链路与客户端日志证据','mode':'timeout-workflow','scope':'circles 超时调查 Demo；基于官方查询和证据规则'}
    enrich_client_logs(case,row,ticket['owner'],cookie,progress)
    persist_case(ticket['owner'],case)
    return {'case':case}


def bundled_cases():
    path=WEB/'assets'/'evidence.js'
    if not path.is_file():path=ROOT/'assets'/'evidence.js'
    match=re.search(r'window\.TraceEvidenceCases\s*=\s*(\[.*\])\s*;?\s*$',path.read_text(),re.S)
    return json.loads(match.group(1)) if match else []


def persist_case(actor,case):
    retained_review(case)
    try:
        case['data']['collection']['savedToAccount']=True
        case['data']['collection']['visibility']='company-shared'
        case['data']['collection']['queryActorRef']=actor_ref(actor)
        case['data']=case_store.shared_view(case)['data']
        case_store.save(actor,case)
    except Exception:
        case['data']['collection']['savedToAccount']=False
        case['data']['collection']['saveError']='共享案件保存暂不可用；当前证据可导出，刷新后可能丢失。'


def retained_review(case):
    """Expose the same source-bound review on saved cases and freshly collected cases."""
    from scripts.case_review import attach_review, attach_resolution
    path=WEB/'assets'/'timeout-review.json'
    if not path.is_file():path=ROOT/'assets'/'timeout-review.json'
    case=attach_review(case,path)
    resolution=WEB/'assets'/'timeout-resolution.json'
    if not resolution.is_file():resolution=ROOT/'assets'/'timeout-resolution.json'
    return attach_resolution(case,resolution)


def enrich_client_logs(case,row,actor,cookie,progress):
    from scripts.vesta_evidence import VestaEvidence, attach
    old=case['data'].get('clientSalvage')
    if not old:
        try:
            saved=case_store.find(actor,row['data']['traceId'])
            if saved and (saved['data']['collection'].get('queryActorRef')==actor_ref(actor) or not saved['data']['collection'].get('queryActorRef') and actor==LEGACY_AUTH_EMAIL):old=saved['data'].get('clientSalvage')
        except Exception:pass
    if not old and actor==LEGACY_AUTH_EMAIL:
        old=next((c['data'].get('clientSalvage') for c in bundled_cases() if c['data']['incident']['traceId']==row['data']['traceId']),None)
    adapter=VestaEvidence(str(ROOT/'runtime'/'bin'/'vesta'),process_env(actor),cookie,actor,progress)
    packet=adapter.collect(row,old)
    attach(case,packet)


class SalvageBody(BaseModel):
    model_config=ConfigDict(extra='forbid')
    traceId:str=Field(pattern=r'^(?:[a-f0-9]{16}|[a-f0-9]{32})$')
    occurredAt:str=Field(min_length=10,max_length=50)


def salvage_work(actor,body,cookie,progress):
    try:case=case_store.find(actor,body.traceId)
    except Exception:case=None
    if not case:case=next((c for c in bundled_cases() if c['data']['incident']['traceId']==body.traceId),None)
    if not case:raise RuntimeError('请先定位并采集该异常样本，再补查客户端日志。')
    # Resolve the target from a fresh official APM record, never from user-provided IDs.
    search=search_work(actor,SearchBody(sample=body.traceId,occurredAt=case['data']['incident']['occurredAt']),progress)
    matches=search['candidates']
    if len(matches)!=1:raise RuntimeError('异常样本未唯一命中，无法安全确定客户端日志目标。')
    ticket=TICKETS.pop(matches[0]['selectionToken'])
    ticket['question']=case['data'].get('investigation',{}).get('question','补查这次超时的客户端日志')
    return investigate_work(ticket,progress,cookie)


@app.get('/health')
def health():return {'ok':True,'service':'trace-live-query','toolsBundled':APM.is_file() and XRAY.is_file(),'nodeAvailable':bool(shutil.which('node'))}


@app.get('/api/capabilities')
def capabilities(request:Request):
    user=_require_user(request.headers.get('decrypted-userinfo'))
    return {'liveQuery':True,'canQuery':bool(identity(request)),'application':'circles','resultsPrivate':False,'caseVisibility':'company-shared','persistentResults':True,'investigationMode':'evidence-agent','agent':{'configured':trace_agent.ai_ready(),'tools':list(trace_agent.TOOLS),'maxToolCalls':trace_agent.MAX_STEPS,'sources':['APM','XRAY','Vesta'],'readOnly':True},'user':{'name':user.get('name') or identity(request),'avatar':user.get('avatar') or '', 'email':identity(request)}}


@app.get('/api/connections')
def connections(request:Request):
    actor=signed_in(request)
    with STATE_LOCK:
        active={tool:{f:value.get(f) for f in ['state','url','code','expiresAt','message']} for (owner,tool),value in AUTH.items() if owner==actor}
    if any(v.get('state')=='pending' for v in active.values()):
        return {'apm':{'connected':False},'xray':{'connected':False},'authorizations':active}
    with cli_lock(actor):states={t:cli_status(t,actor) for t in ['apm','xray']}
    return {**states,'vesta':{'ssoAvailable':bool(vesta_cookie(request)),'authentication':'current-request-sso','verified':False},'authorizations':active}


@app.post('/api/auth/{tool}/start')
def start_auth(tool:str,request:Request):
    actor=signed_in(request,True)
    if tool not in ['apm','xray']:raise HTTPException(404,'未知数据源。')
    if any(j['owner']==actor and j['state'] in ['queued','running'] for j in JOBS.values()):raise HTTPException(409,'查询期间不能切换授权，请等待查询完成。')
    if any(v.get('owner')==actor and v.get('state')=='pending' for v in AUTH.values()):raise HTTPException(409,'请先完成当前授权。')
    state={'owner':actor,'state':'pending','url':None,'code':None,'expiresAt':time.time()+AUTH_TTL,'message':'正在生成官方授权链接。'}
    AUTH[(actor,tool)]=state
    def run():
        with cli_lock(actor):
            cmd=[tool_path(tool)]+(['login','--no-browser','--output','json'] if tool=='apm' else ['auth','login'])
            proc=None;timer=None
            try:
                proc=subprocess.Popen(cmd,env=process_env(actor),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1,start_new_session=True)
                def stop():
                    if proc.poll() is None:
                        try:os.killpg(proc.pid,signal.SIGTERM)
                        except ProcessLookupError:pass
                timer=threading.Timer(AUTH_TTL,stop);timer.start()
                chars=0
                for line in proc.stdout:
                    chars+=len(line)
                    if chars>300000:stop();break
                    for url in re.findall(r'https://[^\s<>"\\]+',line):
                        url=url.rstrip(').,');u=urlsplit(url)
                        if u.hostname and u.hostname.endswith('.xiaohongshu.com') and any(k in u.path.lower() for k in ['auth','login','device']):
                            state['url']=url
                            code=(parse_qs(u.query).get('user_code') or parse_qs(u.query).get('userCode') or [None])[0]
                            if code:state['code']=code
                            state['message']='请打开官方链接，用当前 SSO 账号完成授权。'
                proc.wait(timeout=5)
                connected=cli_status(tool,actor)['connected']
                state['state']='complete' if connected else 'error'
                state['message']='授权完成。' if connected else '授权未完成、已过期或账号不匹配，请重新发起。'
            except Exception:
                state['state']='error';state['message']='授权未完成，请重试。'
            finally:
                if timer:timer.cancel()
    POOL.submit(run)
    return {'started':True,'tool':tool}


@app.post('/api/search')
def search(body:SearchBody,request:Request):
    actor=signed_in(request,True);parse_search(body)
    return create_job(actor,lambda progress:search_work(actor,body,progress))


@app.post('/api/investigate')
def investigate(body:InvestigateBody,request:Request):
    actor=signed_in(request,True);prune()
    with STATE_LOCK:
        ticket=TICKETS.get(body.selectionToken)
        if not ticket or ticket['owner']!=actor:raise HTTPException(404,'候选样本已过期，请重新查询。')
    cookie=vesta_cookie(request)
    return create_job(actor,lambda progress:investigate_work(ticket,progress,cookie))


def vesta_cookie(request):
    for item in request.headers.get('cookie','').split(';'):
        key,sep,value=item.strip().partition('=')
        if key=='common-internal-access-token-prod' and sep:
            return key+'='+value
    return ''


@app.get('/api/cases')
def saved_cases(request:Request):
    actor=signed_in(request)
    try:return {'cases':[retained_review(c) for c in case_store.list_cases(actor)],'persistent':True,'visibility':'company-shared'}
    except Exception:raise HTTPException(503,'案件存储暂不可用，已有证据可通过报告导出。')


@app.post('/api/salvage')
def salvage(body:SalvageBody,request:Request):
    actor=signed_in(request,True)
    cookie=vesta_cookie(request)
    return create_job(actor,lambda progress:salvage_work(actor,body,cookie,progress))


@app.get('/api/jobs/{job_id}')
def job_status(job_id:str,request:Request):
    actor=signed_in(request);prune();job=JOBS.get(job_id)
    if not job or job['owner']!=actor:raise HTTPException(404,'查询不存在或已过期。')
    return public_job(job)


class AgentBody(BaseModel):
    model_config=ConfigDict(extra='forbid')
    question:str=Field(min_length=1,max_length=14000)
    threadId:Optional[str]=Field(default=None,pattern=r'^[a-f0-9]{32}$')


@app.get('/api/agent/threads')
def agent_threads(request:Request):
    actor=signed_in(request)
    try:return {'threads':case_store.list_threads(actor),'visibility':'company-shared'}
    except Exception:raise HTTPException(503,'调查记录存储暂不可用。')


@app.get('/api/agent/health')
def agent_analysis_health(request:Request):
    signed_in(request)
    return trace_agent.analysis_health()


@app.get('/api/agent/threads/{thread_id}')
def agent_thread(thread_id:str,request:Request):
    actor=signed_in(request)
    if not re.fullmatch(r'[a-f0-9]{32}',thread_id):raise HTTPException(404)
    try:item=case_store.get_thread(actor,thread_id)
    except Exception:raise HTTPException(503,'调查记录暂不可用。')
    if not item:raise HTTPException(404,'调查记录不存在。')
    thread={**item['thread'],'whiteScreenPolicy':trace_agent.white_screen_policy(item['thread'].get('evidence',[]))}
    return {'thread':thread,'canContinue':item['canContinue']}


@app.post('/api/agent/run')
def agent_run(body:AgentBody,request:Request):
    actor=signed_in(request,True)
    if not body.question.strip():raise HTTPException(422,'请描述要排查的问题。')
    if not trace_agent.ai_ready():raise HTTPException(503,'Agent 分析服务尚未就绪，请稍后重试。')
    refs={}
    thread={'id':secrets.token_hex(16),'createdAt':trace_agent.now(),'rounds':[],'evidence':[],'messages':[]}
    if body.threadId:
        try:item=case_store.get_thread(actor,body.threadId)
        except Exception:raise HTTPException(503,'调查记录暂不可用。')
        if not item:raise HTTPException(404,'调查记录不存在。')
        if not item['canContinue']:raise HTTPException(409,'这是共享调查；请新建调查，查询将使用你自己的数据源授权。')
        thread=item['thread'];refs=item['refs']
        if any(j.get('agentThreadId')==body.threadId and j['state'] in ['running','queued'] for j in JOBS.values()):
            raise HTTPException(409,'这份调查正在进行中，请等待本轮完成。')
    cookie=vesta_cookie(request)
    def work(progress):
        def factory(privacy):
            runner=trace_agent.ToolRunner(actor,process_env(actor),tool_path('apm'),tool_path('xray'),cli_status,cookie,privacy,progress)
            # Restore only sanitized, actually observed hosts from previous rounds.
            for evidence in thread.get('evidence',[]):privacy.clean(evidence.get('result',{}))
            return runner
        return trace_agent.run(thread,refs,body.question,factory,progress,lambda payload,private:case_store.save_thread(actor,payload,private))
    started=create_job(actor,work,verify=False)
    JOBS[started['jobId']]['agentThreadId']=thread['id']
    return {**started,'threadId':thread['id']}


@app.get('/')
def index(request:Request):
    identity(request)
    return FileResponse(WEB/'index.html',media_type='text/html')


@app.get('/assets/{filename}')
def asset(filename:str,request:Request):
    identity(request)
    if not re.fullmatch(r'[a-zA-Z0-9_.-]+',filename):raise HTTPException(404)
    path=WEB/'assets'/filename
    if not path.is_file():raise HTTPException(404)
    return FileResponse(path)
