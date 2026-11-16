#!/usr/bin/env python3
"""Read-only APM + XRAY acquisition. No credentials are read by this script."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import sys
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

ZONE = ZoneInfo('Asia/Shanghai')
SOURCE_URL = 'https://tracker.devops.xiaohongshu.com/apm/js-error-monitor?startTime=2026-10-28T00:00&endTime=2026-11-05T10:09&applicationName=circles&timeType=dateTime&secInterval=3600&periodType=previousPeriod&childDate=2026-11-01&metricName=jsErrorCount&listType=jsErrorDetailList&childDateStart=2026-10-28&childDateEnd=2026-11-04&errorMessage=includes__timeout+of+5000ms+exceeded'
TRACE = re.compile(r'^(?:[0-9a-f]{16}|[0-9a-f]{32})$')
ALLOWED = {
    'rn_load_phase_track': ['rnStage', 'errorMsg', 'context_bizBundleStatus', 'container_hammerBundleStatus', 'container_hammerVersion', 'context_bizPatchUpdate', 'context_bizPreFetch', 'container_jsEngine', 'container_type', 'context_bizType', 'isSuccess'],
    'hybridPageView': ['isSpa','containerSubType','containerType'],
    'hybridStability': ['stageName','containerType','stayTime','loadSuccess'],
    'hybridPvWithRollbackInfo': ['type','switch_latest_fail_error'],
    'httpRequestTiming': ['status','errorMsg','duration','code','apiPrefetchType','matchedPath','traceId','method','errorType','url','requestStartTime','requestEndTime'],
    'infraJsError': ['type','errorColNumber','errorFilePath','errorExtra','errorMessage','errorStack','errorLevel','errorType','errorLineNumber'],
    'circle_home_stability': ['reason','stage','scene','status'],
    'paintTiming': ['largestContentfulPaint','firstContentfulPaint','lcpResourceLoadDelay','lcpResourceRT','lcpRenderDelay','lcpElement','lcpUrl','isBaseHitCache','isBizHitCache','coreHttpRequestStart','coreHttpRequestEnd','pageRenderFcpFramework','pageRenderLcpFramework','routerStart'],
    'hybridPageEnd': ['stayDuration','fmpLoad','firstMeaningfulPaint','pageSuccess','scene','accessType'],
    'hybridWhiteScreen': ['type','nodeCheck','containerSubType','errorType','containerType','isSpa','ratio','time','captureDuration','parseDuration'],
}
NAMES = {'httpRequestTiming':'HTTP 请求记录','infraJsError':'JS 错误记录','rn_load_phase_track':'RN 加载阶段','hybridPageView':'进入圈子首页','hybridStability':'容器稳定性记录','hybridPvWithRollbackInfo':'回滚状态记录','circle_home_stability':'圈子稳定性记录','paintTiming':'页面渲染记录','hybridPageEnd':'页面退出记录','hybridWhiteScreen':'白屏检测记录'}

def sanitize_text(s):
    s = re.sub(r'/var/mobile/Containers/Data/Application/[A-Fa-f0-9-]+/', '<APP_SANDBOX>/', s)
    s = re.sub(r'/Users/Shared/cirunner/builds/[^\s)]+/InternalBytecode.js', '<HERMES_RUNTIME>/InternalBytecode.js', s)
    return s

class Collector:
    def __init__(self, args, apm=None, xray=None):
        self.a = args
        self.audit = []
        self.apm = apm or shutil.which('apm-cli')
        self.xray = xray or shutil.which('xray-cli')
        self.process_env = None
        self.on_progress = None
        self.last_query_at = {}
        if not self.apm or not self.xray:
            raise RuntimeError('需要安装官方 apm-cli 与 xray-cli，并先完成各自登录。')

    def query(self, tool, args, title, scope, _retry_allowed=True):
        cmd = [self.apm if tool == 'apm' else self.xray]
        if tool == 'xray': cmd += ['--output-format','json']
        cmd += args
        started = dt.datetime.now(ZONE).isoformat(timespec='seconds')
        remaining = 1.0-(time.monotonic()-self.last_query_at.get(tool,0))
        if remaining>0:time.sleep(remaining)
        if self.on_progress: self.on_progress(title)
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=90, env=self.process_env)
        self.last_query_at[tool]=time.monotonic()
        try: obj = json.loads(p.stdout)
        except json.JSONDecodeError: obj = None
        success = p.returncode == 0 and isinstance(obj, dict) and obj.get('success', True) is not False
        safe = [Path(cmd[0]).name, *cmd[1:]]
        for flag in ['--user-id','--session-id']:
            if flag in safe: safe[safe.index(flag)+1] = '<REDACTED>'
        stderr = '\n'.join(l for l in p.stderr.splitlines() if l.startswith('错误:'))
        audit = {'id': 'Q-'+str(len(self.audit)+1).zfill(2), 'title': title, 'tool':tool, 'command':safe, 'queriedAt':started, 'scope':scope, 'exitCode':p.returncode, 'success':success, 'responseSha256':hashlib.sha256(p.stdout.encode()).hexdigest(), 'requestId':obj.get('requestId') if obj else None, 'error':stderr[:800] if not success else ''}
        self.audit.append(audit)
        if not success:
            # Authentication / permission / rate failures are never retried here.
            audit['error'] = audit['error'] or ((obj or {}).get('error',{}).get('message')) or '查询未成功，不能当作空结果。'
            limited = p.returncode==6 or ((obj or {}).get('error') or {}).get('code')=='RATE_LIMITED' or bool(re.search(r'HTTP 429|rate limit exceeded',p.stderr,re.I))
            if limited and _retry_allowed:
                audit['retryAfterSeconds']=61
                if self.on_progress:self.on_progress(title+'：平台限流，等待 61 秒后重试一次')
                time.sleep(61)
                return self.query(tool,args,title+'（限流后重试）',scope,_retry_allowed=False)
            if tool == 'apm': raise RuntimeError(audit['error'])
            return None, audit
        return obj.get('data',obj), audit

    def apm_record(self, log, idx, q, *, session_ref='', comparison=False):
        measurement = log['measurementName']
        raw = log.get('data') or {}
        keep = ALLOWED.get(measurement, [])
        payload = {}
        for k in keep:
            if k not in raw: continue
            v = raw[k]
            if k == 'url': v = urlsplit(str(v))._replace(query='',fragment='').geturl()
            elif isinstance(v,str): v = sanitize_text(v)
            payload[k]=v
        trace = raw.get('traceId') or ''
        trace = trace.lower() if isinstance(trace,str) and TRACE.fullmatch(trace.lower()) and set(trace) != {'0'} else ''
        endpoint = raw.get('matchedPath') or urlsplit(str(raw.get('url',''))).path
        r = {'id':'APM-'+str(idx).zfill(3), 'source':'monitor' if measurement in ['httpRequestTiming','infraJsError'] else 'client', 'type':'http' if measurement=='httpRequestTiming' else 'session-event', 'title':NAMES.get(measurement,measurement), 'measurement':measurement, 'occurredAt':log.get('time'), 'timestamp':log.get('timestamp'), 'traceId':trace, 'requestId':'', 'endpoint':endpoint, 'method':raw.get('method',''), 'bundle':log.get('artifactVersion',''), 'appVersion':log.get('appVersion',''), 'platform':log.get('platform',''), 'sessionRef':session_ref, 'comparison':comparison, 'queryId':q['id'], 'sourceIndex':idx, 'payload':payload, 'omittedFields':sorted(set(raw)-set(payload)), 'sourceUrl':SOURCE_URL}
        if measurement=='rn_load_phase_track': r['title'] += ' · '+str(raw.get('rnStage',''))
        if measurement=='hybridStability': r['title'] += ' · '+str(raw.get('stageName',''))
        if measurement=='circle_home_stability': r['title'] += ' · '+str(raw.get('stage',''))
        if measurement=='httpRequestTiming':
            r['reportedDurationMs']=raw.get('duration')
            r['durationMs']=raw.get('duration') if isinstance(raw.get('duration'),(int,float)) and raw['duration']>0 else None
        return r

    def gateway(self, trace, host, epoch, title):
        start,end=int(epoch/1000)-300,int(epoch/1000)+300
        args=['log','query','--table','rgw',f'http_host:{host} AND x-xray-traceid:{trace}','--st',str(start),'--et',str(end),'--order','asc','--page-size','20']
        data,q=self.query('xray',args,title,{'traceId':trace,'host':host,'startUnixSeconds':start,'endUnixSeconds':end,'limit':20,'table':'rgw'})
        q['returnedCount']=data.get('count') if data else None
        return (data or {}).get('logs') or [],q

    def gateway_records(self, logs, q, *, comparison=False):
        out=[]
        fields=['_time_second_','x-xray-traceid','http_host','request_uri','request_method','response_status','request_time','upstream_response_time','upstream_status','subApplication']
        for j,l in enumerate(logs):
            payload={k:l[k] for k in fields if k in l}
            if 'request_uri' in payload:payload['request_uri']=urlsplit(payload['request_uri']).path
            raw_duration=l.get('request_time')
            duration=round(float(raw_duration)*1000,3) if raw_duration is not None else None
            out.append({'id':f'RGW-{q["id"]}-{j+1:02}','source':'gateway','type':'gateway-request','title':'接入层网关记录','traceId':l.get('x-xray-traceid',''),'requestId':'','endpoint':urlsplit(l.get('request_uri','')).path,'method':l.get('request_method',''),'durationMs':duration,'occurredAt':l.get('_time_second_'),'comparison':comparison,'queryId':q['id'],'payload':payload,'omittedFields':sorted(set(l)-set(fields))})
        return out

    def build(self):
        a=self.a
        sessions,sq=self.query('apm',['log','session','list','--app',a.app,'--user-id',a.user_id,'--st',a.st,'--et',a.et,'--limit','20'],'定位目标用户会话',{'app':a.app,'start':a.st,'end':a.et,'limit':20})
        sq['returnedCount']=sessions.get('total')
        items=sessions.get('sessions') or []
        if a.session_id and not any(s.get('sessionId')==a.session_id for s in items):raise RuntimeError('指定会话不在查询结果内，请核对时间窗。')
        sid=a.session_id
        if not sid:
            candidates=[s for s in items if s.get('sessionId') and (s.get('errorCounts') or {}).get('http',0)]
            if len(candidates)!=1:raise RuntimeError('目标会话不唯一，请指定 --session-id。')
            sid=candidates[0]['sessionId']
        logs,dq=self.query('apm',['log','session','detail','--app',a.app,'--user-id',a.user_id,'--session-id',sid,'--st',a.st,'--et',a.et,'--limit','1000'],'读取完整客户端会话点位',{'app':a.app,'start':a.st,'end':a.et,'limit':1000,'sessionRef':hashlib.sha256(sid.encode()).hexdigest()[:12]})
        all_logs=logs.get('logs') or []
        dq['returnedCount']=len(all_logs)
        dq['possiblyTruncated']=len(all_logs)>=1000
        anchor=[r for r in all_logs if r.get('measurementName')=='httpRequestTiming' and (r.get('data') or {}).get('traceId')==a.trace_id]
        if len(anchor)!=1:raise RuntimeError('指定 Trace 未唯一匹配一个 HTTP 点位，停止生成证据报告。')
        anchor=anchor[0];raw=anchor['data'];trace=raw['traceId'];host=urlsplit(raw.get('url','')).hostname
        if not host:raise RuntimeError('HTTP 点位缺少有效请求域名。')
        ref='session-'+hashlib.sha256(sid.encode()).hexdigest()[:12]
        records=[self.apm_record(l,i+1,dq,session_ref=ref) for i,l in enumerate(all_logs)]
        anchor_record=next(r for r in records if r['type']=='http' and r['traceId']==trace)
        analysis,tq=self.query('xray',['trace','tree','--trace-id',trace,'--mode','analysis'],'下钻本次超时的服务端 Trace',{'traceId':trace,'mode':'analysis'})
        tq['returnedCount']=len((analysis or {}).get('analyzed_spans') or []) if analysis is not None else None
        tq['responseSummary']={'trace_id':trace, 'analyzed_spans':None if analysis is not None and analysis.get('analyzed_spans') is None else '见返回数量；不发布含实例信息的原始 Span'}
        gateway,gq=self.gateway(trace,host,anchor['timestamp'],'查询本次超时的接入层记录')
        records+=self.gateway_records(gateway,gq)
        for n, item in enumerate((analysis or {}).get('analyzed_spans') or []):
            span=item.get('span') or {}; micros=span.get('duration_micros')
            if not isinstance(micros,(int,float)) or micros<0: continue
            payload={k:item.get(k) for k in ['name','app','type','abnormal','slow'] if item.get(k) is not None}
            payload['duration_micros']=micros
            if isinstance(item.get('exception'),str): payload['exception']=sanitize_text(item['exception'])[:4000]
            records.append({'id':'SPAN-'+str(n+1).zfill(3),'source':'server','type':'trace-span','title':str(item.get('name') or '服务端 Span')[:300], 'traceId':trace,'requestId':'','endpoint':'','method':'','durationMs':round(micros/1000,3),'queryId':tq['id'],'payload':payload,'omittedFields':['pod_name','ip','logs','exception_data','paths']})
        control=None
        if a.control_trace:
            ctl,cq=self.query('apm',['log','search','--app',a.app,'--measurement-name','httpRequestTiming','--st',a.control_st or a.st,'--et',a.control_et or a.et,'--filter','measurement_data.traceId='+a.control_trace,'--limit','5'],'采集独立正常对照请求',{'app':a.app,'traceId':a.control_trace,'start':a.control_st or a.st,'end':a.control_et or a.et,'limit':5})
            ls=ctl.get('logs') or [];cq['returnedCount']=len(ls);cq['coveredFullRange']=ctl.get('coveredFullRange');cq['possiblyTruncated']=len(ls)>=5
            exact=[l for l in ls if (l.get('data') or {}).get('traceId')==a.control_trace]
            if len(exact)!=1:raise RuntimeError('对照 Trace 未唯一匹配一个 HTTP 点位。')
            cl=exact[0];cr=self.apm_record(cl,1,cq,comparison=True);cr['id']='CONTROL-APM-001';cr['title']='独立正常请求 · 客户端记录'
            gw,cgq=self.gateway(a.control_trace,urlsplit(cl['data']['url']).hostname,cl['timestamp'],'查询独立正常对照的网关记录')
            gr=self.gateway_records(gw,cgq,comparison=True)
            control={'anchor':cr,'gateway':gr,'gatewayQuery':cgq,'clientQuery':cq}
            records += [cr,*gr]
        threshold_match=re.search(r'timeout of (\d+)ms',str(raw.get('errorMsg','')))
        capture=dt.datetime.now(ZONE).isoformat(timespec='seconds')
        incident={'id':'TRACE-'+str(anchor['timestamp']),'title':'圈子首页 · 基础信息请求超时','anchorRecordId':anchor_record['id'],'occurredAt':anchor.get('time'),'timestamp':anchor.get('timestamp'),'durationMs':anchor_record['durationMs'],'reportedDurationMs':raw.get('duration'),'timeoutThresholdMs':int(threshold_match.group(1)) if threshold_match else None,'traceId':trace,'requestId':'','endpoint':anchor_record['endpoint'],'method':raw.get('method',''),'host':host,'bundle':a.app+'@'+anchor.get('artifactVersion',''),'appVersion':anchor.get('appVersion',''),'platform':anchor.get('platform',''),'device':'设备型号未由 CLI 返回','environment':'','sessionRef':ref,'error':raw.get('errorMsg','')}
        data={'schemaVersion':2,'provenance':'real-snapshot','application':a.app,'incident':incident,'target':{},'records':records,'queries':self.audit,'collection':{'capturedAt':capture,'sourceUrl':SOURCE_URL,'queryEnvironment':'prod','region':'cn','clientLogCount':len(all_logs),'source':'官方 apm-cli + xray-cli 实际查询','apmVersion':'0.1.10','xrayVersion':'0.1.31','privacy':'用户 ID、设备唯一标识、IP、路由业务参数及本机沙盒路径已移除；Trace ID 保留用于复查。','recordIds':'APM / RGW 编号为本地证据编号，不是平台原始日志 ID。','semantics':'真实采集快照；网页重新核对仅运行关联规则，不会重新查询平台。'},'downstream':{'traceQueryId':tq['id'],'traceQuerySuccess':tq['success'],'spanCount':tq['returnedCount'],'gatewayQueryId':gq['id'],'gatewayQuerySuccess':gq['success'],'gatewayCount':gq['returnedCount']}}
        cases=[{'key':'real-timeout','label':'真实超时 · 圈子首页','caption':'客户端异常与后端查询缺口','data':data}]
        if control:
            cd=json.loads(json.dumps(data));ca=json.loads(json.dumps(control['anchor']));ca['comparison']=False
            cg=json.loads(json.dumps(control['gateway']))
            for r in cg:r['comparison']=False
            cd['records']=[ca,*cg,json.loads(json.dumps(anchor_record))];cd['records'][-1]['comparison']=True
            ci=cd['incident'];ci.update({'id':'TRACE-CONTROL-'+str(ca['timestamp']),'title':'独立正常对照 · 同一接口','anchorRecordId':ca['id'],'occurredAt':ca['occurredAt'],'timestamp':ca['timestamp'],'durationMs':ca['durationMs'],'reportedDurationMs':ca['reportedDurationMs'],'timeoutThresholdMs':None,'traceId':ca['traceId'],'sessionRef':'','bundle':a.app+'@'+ca['bundle'],'appVersion':ca['appVersion'],'platform':ca['platform'],'error':''})
            cd['downstream']={'traceQueryId':None,'traceQuerySuccess':False,'spanCount':None,'gatewayQueryId':control['gatewayQuery']['id'],'gatewayQuerySuccess':control['gatewayQuery']['success'],'gatewayCount':control['gatewayQuery']['returnedCount']}
            cd['collection']['clientLogCount']=1
            cases.append({'key':'real-control','label':'真实对照 · 请求成功','caption':'客户端 '+str(ca['durationMs'])+' ms · 同 Trace 网关记录','data':cd})
        return cases

    def run(self):
        cases=self.build()
        data=cases[0]['data'];gq=data['downstream'];capture=data['collection']['capturedAt']
        output=Path(self.a.output);output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text('/* Collected with official read-only CLIs. Sanitized snapshot; not simulated. */\nwindow.TraceEvidenceCases = '+json.dumps(cases,ensure_ascii=False,indent=2)+';\n')
        print(json.dumps({'cases':len(cases),'clientLogs':data['collection']['clientLogCount'],'timeoutGatewayCount':gq['gatewayCount'],'timeoutSpanCount':gq['spanCount'],'capturedAt':capture,'output':str(output)},ensure_ascii=False))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for k in ['app','user-id','st','et','trace-id']:p.add_argument('--'+k,required=True)
    for k in ['session-id','control-trace','control-st','control-et']:p.add_argument('--'+k)
    p.add_argument('--output',default='assets/evidence.js');a=p.parse_args()
    for t in [a.trace_id,a.control_trace]:
        if t and not TRACE.fullmatch(t):p.error('Trace ID 必须是 16 或 32 位小写十六进制。')
    try:Collector(a).run()
    except Exception as e:print('采集未完成：'+str(e),file=sys.stderr);raise SystemExit(1)
if __name__=='__main__':main()
