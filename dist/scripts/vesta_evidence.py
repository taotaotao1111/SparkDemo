"""Official Vesta CLI adapter. Raw logs and identity stay out of public cases."""
import datetime as dt
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from zoneinfo import ZoneInfo

ZONE=ZoneInfo('Asia/Shanghai')
SOURCE='https://vesta.devops.xiaohongshu.com/xhs/log/log-salvage'


def network_metrics(line,trace,endpoint,method):
    """Export an allowlist, never query strings, headers, IPs or business payloads."""
    if 'INFRA-NetworkTotalMetrics:' not in line:return None
    try:raw=json.JSONDecoder().raw_decode(line[line.index('{'):])[0]
    except (ValueError,TypeError):return None
    traces=[]
    if not isinstance(raw,dict) or not isinstance(raw.get('httpTraces'),list):return None
    for item in raw['httpTraces']:
        if not isinstance(item,dict) or item.get('xrayTraceId','').lower()!=trace.lower() or item.get('path')!=endpoint or item.get('method')!=method:continue
        safe={k:item[k] for k in ['hasResponse','hasError','firstInterceptorStart','fetchStart','requestStart','requestEnd','responseStart','responseEnd','isReusedConnection'] if isinstance(item.get(k),(int,float)) and not isinstance(item.get(k),bool)}
        safe.update(path=endpoint,method=method,xrayTraceId=trace)
        traces.append(safe)
    if not traces:return None
    safe={k:raw[k] for k in ['callDuration','httpCode','errorCode','requestCallStartTimestamp','requestCallEndTimestamp','receiveBytesTotal','sendBytesTotal'] if isinstance(raw.get(k),(int,float)) and not isinstance(raw.get(k),bool)}
    if raw.get('callStatus') in ['callFailed','callSuccess']:safe['callStatus']=raw['callStatus']
    safe['httpTraces']=traces
    return safe


def redact(text,identifiers=()):
    for value in identifiers:
        if value:text=text.replace(str(value),'<REDACTED>')
    text=re.sub(r'(?i)(?:Bearer\s+|apmc_)[\w.=-]+','<REDACTED>',text)
    text=re.sub(r'(?i)((?:access_token|refresh_token|cookie|authorization|device_?id|user_?id|uid|token|password|secret)\s*[=:]\s*)[^\s,;\]}]+',r'\1<REDACTED>',text)
    text=re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b','<IP>',text)
    text=re.sub(r'(?<=\b)[a-fA-F0-9]{24}(?=\b)','<BUSINESS_ID>',text)
    text=re.sub(r'(https?://[^\s?]+)\?[^\s]+',r'\1?<PARAMS_REMOVED>',text)
    return text


class VestaEvidence:
    def __init__(self,binary,env,cookie,actor,progress):
        self.binary=binary;self.env=dict(env);self.progress=progress;self.audit=[];self.identifiers=[]
        # The current authenticated request supplies SSO; no credential is persisted.
        self.env.pop('VESTA_COOKIE',None)
        if cookie:self.env['VESTA_COOKIE']=cookie
        self.env['VESTA_RECEIVER']=actor
        self.env['TZ']='Asia/Shanghai'
        self.cookie=cookie

    def query(self,args,title,scope,timeout=65):
        self.progress(title)
        started=dt.datetime.now(ZONE).isoformat(timespec='seconds')
        safe=list(args)
        for flag in ['--user-id','--device-id','--cookie']:
            if flag in safe:safe[safe.index(flag)+1]='<REDACTED>'
        try:
            p=subprocess.run([self.binary]+args+['--json'],env=self.env,capture_output=True,text=True,timeout=timeout)
            raw=p.stdout;code=p.returncode;error=redact(p.stderr,self.identifiers)[:500]
            data=json.loads(raw) if raw.strip() else None
        except subprocess.TimeoutExpired:
            raw='';code=124;error='官方 CLI 查询超时，不能解释为空结果。';data=None
        except (ValueError,OSError):
            raw='';code=1;error='官方 CLI 未返回有效数据或工具未就绪。';data=None
        audit={'id':f'VESTA-Q-{len(self.audit)+1:02}','tool':'vesta','title':title,'command':['vesta']+safe+['--json'],'queriedAt':started,'scope':scope,'exitCode':code,'success':code==0,'responseSha256':hashlib.sha256(raw.encode()).hexdigest(),'error':error if code else ''}
        self.audit.append(audit)
        return data,audit

    def collect(self,row,previous=None):
        raw=row['data'];trace=raw['traceId'];uid=row['userId'];self.identifiers=[uid,row.get('sessionId')]
        platform={'ios':'ios','android':'android','harmony':'harmony'}.get(str(row.get('platform','')).lower())
        epoch=row['timestamp'];start=epoch-300000;end=epoch+300000
        fmt=lambda n:dt.datetime.fromtimestamp(n/1000,ZONE).isoformat(timespec='milliseconds')
        packet={'source':'Vesta 官方 CLI 0.2.0','sourceUrl':SOURCE,'traceId':trace,'queriedAt':dt.datetime.now(ZONE).isoformat(timespec='seconds'),'status':'unavailable','statusLabel':'尚未取得客户端日志','summary':'','taskId':None,'excerpts':[],'coverage':{'requestedStart':fmt(start),'requestedEnd':fmt(end),'coversIncident':None,'description':'尚未验证客户端日志覆盖范围。'},'associationBasis':'由原始 APM HTTP 样本定位用户及平台；同用户不等于同请求，需核对日志中的 Trace / Request ID。','gaps':[],'queries':self.audit}
        if not self.cookie:
            packet.update(status='authentication-required',statusLabel='等待当前账号 SSO',summary='当前请求未携带可用于 Vesta 的官方 SSO，未发起客户端查询。')
            packet['gaps']=['请在当前浏览器完成公司 SSO 登录后重试；没有将预置任务状态冒充本次查询。']
            return packet
        if not platform:
            packet.update(summary='样本平台不能映射到 Vesta 支持的平台，未发起回捞。');return packet
        if previous:
            self.audit.extend(previous.get('queries',[]))
        # Prefer an already associated task to avoid duplicate dispatch on refresh.
        task=None
        if previous and str(previous.get('taskId','')).isdigit():
            item,q=self.query(['log','list','--task-id',str(previous['taskId'])],'核对已有客户端回捞任务',{'taskId':str(previous['taskId'])})
            if q['success']:
                items=item if isinstance(item,list) else [item]
                task=next((t for t in items if isinstance(t,dict) and t.get('userId')==uid and t.get('platform')==platform),None)
                if not task:
                    packet.update(status='target-mismatch',statusLabel='目标未通过核对',summary='既有任务未能核对为本次样本的用户和平台，未下载或创建任务。');return packet
            else:
                packet.update(status='query-failed',statusLabel='查询失败',summary=q['error']);return packet
        if not task:
            since=dt.datetime.fromtimestamp(epoch/1000,ZONE).strftime('%Y-%m-%d 00:00:00')
            items,q=self.query(['log','list','--user-id',uid,'--platform',platform,'--from',since,'--max-pages','2'],'查找已有客户端日志回捞',{'platform':platform,'from':since,'maxPages':2})
            if not q['success']:
                packet.update(status='query-failed',statusLabel='查询失败',summary=q['error']);return packet
            items=items if isinstance(items,list) else (items or {}).get('tasks',[])
            q['returnedCount']=len(items)
            eligible=[t for t in items if t.get('userId')==uid and t.get('platform')==platform and t.get('type')=='log_salvage']
            # An existing unrelated task is a candidate; never assume it covers this incident.
            marked=[t for t in eligible if ('迹线Trace' in str(t.get('comment','')) or 'Trace '+trace in str(t.get('comment','')))]
            task=next(iter(marked),None) or next((t for t in eligible if t.get('hasLog')),None)
        if not task:
            created,q=self.query(['log','salvage','--platform',platform,'--user-id',uid,'--comment','Trace '+trace+' 超时证据补全','--deadline',str(start),'--anchor',str(end),'--count','10','--no-wait'],'发起异常时刻的客户端日志回捞',{'platform':platform,'app':'xhs','region':'cn','start':fmt(start),'end':fmt(end),'count':10,'targetScope':'原始样本用户的全部同平台设备'})
            if not q['success'] or not isinstance(created,dict) or not str(created.get('taskId','')).isdigit():
                packet.update(status='creation-unconfirmed',statusLabel='创建未确认',summary=q['error'] or '官方返回未包含有效任务 ID，未自动重复创建。');return packet
            packet['taskId']=str(created['taskId'])
            task,q=self.query(['log','list','--task-id',packet['taskId'],'--wait','30'],'等待客户端日志回传',{'taskId':packet['taskId'],'waitSeconds':30},timeout=45)
            if isinstance(task,list):task=next(iter(task),None)
        if not isinstance(task,dict):
            packet.update(status='query-failed',statusLabel='任务状态未取得',summary='未取得有效任务状态，不能判断日志是否存在。');return packet
        packet['taskId']=str(task.get('id') or packet['taskId'] or '')
        packet['task']={k:task.get(k) for k in ['state','stateMsg','platform','appId','type','hasLog','clientLogCount','clientLogStartTime','salvageTime','uploadTime','decryptVersion','decryptMsg']}
        packet['status']='uploaded' if task.get('hasLog') else 'pending'
        packet['statusLabel']='日志已上传，核对覆盖范围' if task.get('hasLog') else ('已发起，等待客户端上传' if task.get('state')==1 else '平台状态 '+str(task.get('state')))
        packet['summary']='已实际查询 Vesta 任务 '+packet['taskId']+'；客户端日志文件数 '+str(task.get('clientLogCount') or 0)+'。'
        packet['coverage']['observedStart']=task.get('clientLogStartTime') or None
        if task.get('hasLog'):
            with tempfile.TemporaryDirectory(prefix='trace-vesta-') as folder:
                downloaded,q=self.query(['log','download','--task-id',packet['taskId'],'--wait','45','--out',folder],'下载并核对客户端日志',{'taskId':packet['taskId'],'waitSeconds':45},timeout=150)
                if q['success']:self.extract(folder,row,packet)
                else:packet['gaps'].append('日志下载未完成；'+q['error'])
        else:
            packet['gaps'].append('任务创建不等于回捞成功；目标客户端尚未回传可下载日志，无法核实请求取消或网络阶段。')
        if not packet['excerpts']:packet['gaps'].append('未取得包含本次 Trace 的客户端日志片段；同用户、同平台或时间接近不构成请求级证据。')
        packet['queriedAt']=dt.datetime.now(ZONE).isoformat(timespec='seconds')
        return packet

    def extract(self,folder,row,packet):
        trace=row['data']['traceId'];size=0;files=0;truncated=False;hits=0
        endpoint=row['data'].get('url','').split('?')[0]
        if endpoint.startswith('http'):endpoint='/'+endpoint.split('/',3)[-1]
        endpoint=row['data'].get('path') or endpoint
        # The caller's HTTP data uses url/path depending on official CLI version.
        endpoint=endpoint or packet.get('endpoint','')
        method=row['data'].get('method','GET')
        paths=sorted(p for p in Path(folder).rglob('*') if p.is_file() and not p.is_symlink() and p.suffix.lower() in ['.log','.txt'])
        for path in paths:
            size+=path.stat().st_size
            if size>40*1024*1024:
                truncated=True;break
            blob=path.read_bytes();files+=1
            if b'\0' in blob[:1000]:continue
            text=blob.decode('utf-8',errors='replace')
            for index,line in enumerate(text.splitlines(),1):
                if trace.lower() not in line.lower():continue
                hits+=1
                metrics=network_metrics(line,trace,endpoint,method)
                phase=next((p for p in ['Multiplexer_Init_crn','FailWithoutMetrics','Aborted','Start'] if re.search(r'\b'+p+r'\b',line)),None)
                if not metrics and not phase:continue
                if len(packet['excerpts'])>=12:continue
                prefix=re.match(r'\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}',line)
                excerpt={'title':'客户端网络指标' if metrics else '客户端 '+phase,'traceId':trace,'file':'log-'+hashlib.sha256(path.name.encode()).hexdigest()[:8]+path.suffix,'lineStart':index,'fileSha256':hashlib.sha256(blob).hexdigest(),'association':'日志含精确 Trace；网络指标另核对接口及方法'}
                if metrics:
                    excerpt['networkMetrics']=metrics
                    excerpt['text']=json.dumps(metrics,ensure_ascii=False,indent=2)
                    excerpt['timestamp']=metrics.get('requestCallEndTimestamp')
                    packet['networkMetrics']=metrics
                else:excerpt['text']=(prefix.group(0)+' ' if prefix else '')+'TraceID: '+trace+' event='+phase+'；其他字段未导出'
                if excerpt.get('timestamp'):
                    excerpt['occurredAt']=dt.datetime.fromtimestamp(excerpt['timestamp']/1000,ZONE).isoformat(timespec='milliseconds')
                packet['excerpts'].append(excerpt)
        packet['downloadedFileCount']=len(paths)
        packet['scannedFileCount']=files
        packet['scanTruncated']=truncated
        packet['exactTraceLineCount']=hits
        packet['exportedExcerptCount']=len(packet['excerpts'])
        packet['status']='ready' if packet['excerpts'] else 'downloaded-unmatched'
        packet['statusLabel']='已取得同 Trace 日志片段' if packet['excerpts'] else '已下载，未找到本次 Trace'
        packet['summary']='平台源日志 '+str(packet.get('task',{}).get('clientLogCount') or 0)+' 个；已下载 '+str(len(paths))+' 个解密明文文件，精确 Trace 命中 '+str(hits)+' 行，导出 '+str(len(packet['excerpts']))+' 条白名单片段。'
        packet['coverage']['description']='已下载 '+str(len(paths))+' 个明文文件，扫描 '+str(files)+' 个；'+('找到同 Trace 记录，仍需核对时间与请求阶段。' if packet['excerpts'] else '已扫描范围内未找到同 Trace 记录，不能确认覆盖本次异常。')+('扫描达到上限，不能视为全量检索。' if truncated else '')
        if packet.get('networkMetrics'):
            m=packet['networkMetrics'];end=m.get('requestCallEndTimestamp')
            packet['coverage']['coversIncident']=bool(end and abs(end-row['timestamp'])<1000)
            packet['coverage']['description']+='网络指标的同 Trace、接口与方法一致；请求结束时间与异常点位相差 '+str(abs(end-row['timestamp']))+' ms。' if end else ''


def attach(case,packet):
    """Attach observed task metadata separately from request-level log evidence."""
    data=case['data'];data['clientSalvage']=packet
    data['queries']=[q for q in data['queries'] if q.get('tool')!='vesta']+packet.get('queries',[])
    data['records']=[r for r in data['records'] if r.get('source')!='salvage']
    task_id=packet.get('taskId');queries=packet.get('queries',[])
    if task_id:
        data['records'].append({'id':'VESTA-TASK-'+str(task_id),'source':'salvage','type':'salvage-task','title':'客户端日志回捞任务','occurredAt':packet.get('queriedAt',''),'traceId':'','requestId':'','queryId':queries[-1]['id'] if queries else '', 'payload':{'taskId':str(task_id),'status':packet.get('statusLabel'),'clientLogCount':packet.get('task',{}).get('clientLogCount',0),'coverage':packet.get('coverage',{}).get('description'),'associationBasis':packet.get('associationBasis')},'sourceUrl':SOURCE})
    for n,excerpt in enumerate(packet.get('excerpts',[]),1):
        data['records'].append({'id':excerpt.get('id') or 'VESTA-LOG-'+str(n).zfill(2),'source':'salvage','type':'client-log','title':excerpt.get('title','客户端日志片段'),'traceId':excerpt.get('traceId',''),'requestId':'','occurredAt':excerpt.get('occurredAt',''),'timestamp':excerpt.get('timestamp'), 'queryId':queries[-1]['id'] if queries else '', 'payload':excerpt,'sourceUrl':SOURCE})
    data['collection']['queryCount']=len(data['queries'])
