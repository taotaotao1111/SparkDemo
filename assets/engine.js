/* Deterministic analysis of actual captured observations. No generated evidence. */
(function(root){
'use strict';
const copy=v=>JSON.parse(JSON.stringify(v));
const sourceNames={monitor:'APM 客户端监控',client:'APM 会话点位',runtime:'运行字段',gateway:'XRAY 接入层网关',server:'XRAY 服务端 Span',salvage:'Vesta 客户端回捞',review:'留存复核证据',business:'业务确认反馈'};
const traceValid=t=>typeof t==='string'&&/^(?:[a-f\d]{16}|[a-f\d]{32})$/i.test(t)&&!/^0+$/.test(t);
function validate(input){
 if(!input||typeof input!=='object'||Array.isArray(input)||!input.incident||!Array.isArray(input.records))throw new Error('需要 incident 对象与 records 数组。');
 const i=input.incident;
 for(const k of ['id','title','anchorRecordId'])if(typeof i[k]!=='string'||!i[k]||i[k].length>500)throw new Error('incident.'+k+' 必须是有效文本。');
 if(input.records.length>1000)throw new Error('最多支持 1000 条记录。');
 for(const k of ['durationMs','timeoutThresholdMs','reportedDurationMs'])if(i[k]!=null&&(typeof i[k]!=='number'||!Number.isFinite(i[k])||i[k]<0||i[k]>86400000))throw new Error(k+' 必须是有效非负毫秒数或 null。');
 for(const k of ['traceId','requestId','endpoint','method','bundle','appVersion','platform','environment','sessionRef','occurredAt','error'])if(i[k]!=null&&typeof i[k]!=='string')throw new Error('incident.'+k+' 必须是文本。');
 const ids=new Set();
 for(const r of input.records){
  if(!r||typeof r!=='object'||Array.isArray(r))throw new Error('每条记录必须是对象。');
  for(const k of ['id','title','source','type'])if(typeof r[k]!=='string'||!r[k]||r[k].length>1000)throw new Error('记录缺少有效 '+k+'。');
  if(ids.has(r.id))throw new Error('证据 ID 重复：'+r.id);ids.add(r.id);
  for(const k of ['traceId','requestId','endpoint','method','sessionRef','bundle','appVersion','platform','queryId','occurredAt'])if(r[k]!=null&&typeof r[k]!=='string')throw new Error(r.id+' 的 '+k+' 必须是文本。');
  for(const k of ['durationMs','reportedDurationMs','timestamp'])if(r[k]!=null&&(typeof r[k]!=='number'||!Number.isFinite(r[k])||r[k]<0))throw new Error(r.id+' 的 '+k+' 必须是有效数值。');
  if(r.payload!=null&&(typeof r.payload!=='object'||Array.isArray(r.payload)))throw new Error(r.id+' 的 payload 必须是对象。');
  for(const k of ['errorMsg','errorMessage','errorType','errorExtra','lcpUrl','rnStage','stage','reason','stageName'])if(r.payload?.[k]!=null&&typeof r.payload[k]!=='string')throw new Error(r.id+' 的 payload.'+k+' 必须是文本。');
  if(r.omittedFields!=null&&(!Array.isArray(r.omittedFields)||r.omittedFields.some(v=>typeof v!=='string')))throw new Error('omittedFields 必须是文本数组。');
 }
 if(!ids.has(i.anchorRecordId))throw new Error('anchorRecordId 未指向已有证据。');
 if(input.queries!=null&&(!Array.isArray(input.queries)||input.queries.length>100))throw new Error('queries 必须为数组，最多 100 项。');
 for(const q of input.queries||[]){if(!q||typeof q!=='object'||typeof q.id!=='string'||typeof q.title!=='string'||typeof q.tool!=='string'||(q.command!=null&&(!Array.isArray(q.command)||q.command.some(v=>typeof v!=='string'))))throw new Error('查询审计格式不正确。');}
 for(const k of ['target','collection','downstream'])if(input[k]!=null&&(typeof input[k]!=='object'||Array.isArray(input[k])))throw new Error(k+' 必须为对象。');
 const output=copy(input);output.target=output.target||{};output.queries=output.queries||[];output.collection=output.collection||{};output.downstream=output.downstream||{};return output;
}
function match(r,i){
 const out=(status,basis,scope)=>({...r,status,basis,scope});
 if(r.type==='investigation-context')return out('context','已核对的独立请求或补查记录；仅作调查上下文，不是本次请求的根因证明','investigation-context');
 if(r.type==='salvage-task')return out('context','实际回捞任务面向样本所属用户与平台；任务创建或状态不证明本次请求行为','salvage-task');
 if(r.type==='client-log'&&traceValid(r.traceId)&&r.traceId.toLowerCase()===String(i.traceId).toLowerCase())return out('matched','客户端日志包含同一 Trace；仍需核对时间、接口与请求阶段','client-log');
 if(r.id===i.anchorRecordId)return out('matched','本次选定的原始 HTTP 点位；Trace ID 来自该记录','anchor');
 if(r.comparison)return out('excluded','独立对照请求，Trace ID 不同；不用于本次异常归因','comparison');
 if(traceValid(r.traceId)&&traceValid(i.traceId)){
  if(r.traceId.toLowerCase()!==i.traceId.toLowerCase())return out('excluded','Trace ID 不同，不能关联到本次链路','other-trace');
  if(r.type==='trace-span'&&r.source==='server')return out('matched','同一 Trace 的服务端 Span；表示链路相关，不等于同一个请求阶段','span');
  if(r.endpoint&&i.endpoint&&r.endpoint!==i.endpoint)return out('candidate','Trace 相同，但接口不同；同一链路可能包含其他请求','trace');
  if(r.method&&i.method&&r.method!==i.method)return out('candidate','Trace 与接口相同，但方法不同，需要核对','trace');
  return out('matched','Trace ID、接口与方法一致；关联同一 Trace，未提供 Request ID','trace');
 }
 if(r.sessionRef&&i.sessionRef&&r.sessionRef===i.sessionRef)return out('context','同一用户会话与查询窗口；仅作为会话上下文，不证明请求因果','session');
 return out('candidate','缺少足够的请求或会话标识，尚不能确认关联','unknown');
}
function analyze(input){
 const data=validate(input),i=data.incident;
 const records=data.records.map(r=>match(r,i)),matched=records.filter(r=>r.status==='matched'),contexts=records.filter(r=>r.status==='context'),excluded=records.filter(r=>r.status==='excluded'),candidates=records.filter(r=>r.status==='candidate');
 const anchor=records.find(r=>r.id===i.anchorRecordId),gateway=matched.filter(r=>r.source==='gateway'),server=matched.filter(r=>r.source==='server');
 const metricsRecord=matched.find(r=>r.type==='client-log'&&r.payload?.networkMetrics?.httpTraces?.some(t=>t.xrayTraceId===i.traceId&&t.path===i.endpoint&&t.method===i.method));
 const metrics=metricsRecord?.payload.networkMetrics,phase=metrics?.httpTraces.find(t=>t.xrayTraceId===i.traceId&&t.path===i.endpoint&&t.method===i.method);
 // Only calculate a phase breakdown when every timestamp belongs to one ordered native request.
 const points=phase&&[phase.firstInterceptorStart,phase.fetchStart,phase.requestStart,phase.requestEnd,metrics.requestCallEndTimestamp];
 const nativeStages=points&&points.every((v,n)=>Number.isFinite(v)&&v>0&&(n===0||v>=points[n-1]))?{recordId:metricsRecord.id,setupMs:points[1]-points[0],beforeSendMs:points[2]-points[1],sendMs:points[3]-points[2],afterSendMs:points[4]-points[3],timestampDurationMs:points[4]-points[0],callDurationMs:metrics.callDuration}:null;
 const review=data.evidenceReview;
 const reviewed=review?.kind==='retained-evidence-review'&&review.binding?.traceId===i.traceId&&review.binding?.timestamp===i.timestamp&&review.binding?.bundle===i.bundle&&review.binding?.endpoint===i.endpoint&&review.binding?.method===i.method&&metricsRecord?.payload.fileSha256===review.binding.nativeFileSha256&&metrics?.requestCallEndTimestamp===review.binding.nativeEndTimestamp&&records.some(r=>r.id===review.nativeEvidenceId&&r.status==='matched');
 const failed=['HTTPClientError','HTTPServerError','HTTPBizError'].includes(anchor.payload?.errorType)||Boolean(i.error)||anchor.payload?.status===0||Number(anchor.payload?.status)>=400;
 const checks=[{key:'bundle',name:'运行版本',actual:i.bundle||'未采集',expected:data.target.bundle||'未指定待验证版本',status:data.target.bundle?(i.bundle===data.target.bundle?'pass':'fail'):'observed'}, {key:'environment',name:'请求泳道',actual:i.environment||'日志未提供',expected:data.target.environment||'未指定；查询 prod 不代表运行泳道',status:i.environment&&data.target.environment?(i.environment===data.target.environment?'pass':'fail'):'unknown'}, {key:'request',name:'请求标识',actual:i.requestId||i.traceId||'未提供',expected:i.requestId?'Request ID':i.traceId?'Trace ID；未提供 Request ID':'补充请求标识',status:i.requestId?'pass':traceValid(i.traceId)?'observed':'unknown'}];
 const facts=[{title:failed?'客户端记录请求失败':'客户端记录 HTTP '+(anchor.payload?.status??'未知'),text:failed?`status=${anchor.payload?.status??'未知'}，errorType=${anchor.payload?.errorType||'未提供'}。status=0 是客户端上报值，不是服务端 HTTP 响应码。`:'这是客户端点位中的响应状态，独立于其他样本。',evidenceIds:[anchor.id]}, {title:'实际上报版本 '+(i.bundle||'未知'),text:'App '+(i.appVersion||'未知')+' · '+(i.platform||'平台未提供')+'。未提供发布目标，不能据此确认修复已生效。',evidenceIds:[anchor.id]}];
 if(i.durationMs==null)facts.push({title:metrics?'APM 耗时缺失，已由原生日志补证':'实测请求耗时缺失',text:'HTTP 点位 duration 原值为 '+String(i.reportedDurationMs??'未上报')+'；'+(i.timeoutThresholdMs?'错误文案中的 '+i.timeoutThresholdMs+' ms 仅作为超时阈值。':'未从该值推导实际耗时。'),evidenceIds:[anchor.id]});
 else facts.push({title:'客户端实测耗时 '+i.durationMs+' ms',text:'来自原始 HTTP 点位的 duration。与其他端计时起点不同。',evidenceIds:[anchor.id]});
 if(gateway.length)facts.push({title:'同 Trace 网关记录 '+gateway.length+' 条',text:gateway.map(r=>(r.payload?.request_time??'未知')+' 秒 / '+(r.durationMs??'未知')+' ms，HTTP '+(r.payload?.response_status??'未知')).join('；')+'。保留原始秒单位，未把差值归因于网络。',evidenceIds:gateway.map(r=>r.id)});
 const js=contexts.filter(r=>r.measurement==='infraJsError'&&r.payload?.errorMessage===i.error&&r.timestamp>=i.timestamp&&r.timestamp-i.timestamp<=100).sort((a,b)=>a.timestamp-b.timestamp)[0];
 if(js)facts.push({title:'同会话出现相同超时错误',text:'JS 错误发生在 HTTP 点位之后 '+(js.timestamp-i.timestamp)+' ms，errorExtra 为 '+(js.payload?.errorExtra||'未提供')+'。这是时序相关证据，不证明请求级因果。',evidenceIds:[anchor.id,js.id]});
 const stability=contexts.filter(r=>r.measurement==='circle_home_stability'&&r.payload?.status===0&&Math.abs(r.timestamp-i.timestamp)<=1000);
 if(stability.length)facts.push({title:'业务稳定性点位记录失败',text:stability.map(r=>(r.payload?.stage||'未知阶段')+'：'+(r.payload?.reason||'未提供原因')).join('；')+'。按点位原值展示，未代替页面录像。',evidenceIds:stability.map(r=>r.id)});
 const paint=contexts.filter(r=>r.measurement==='paintTiming'&&r.timestamp>=i.timestamp&&r.timestamp-i.timestamp<=5000).sort((a,b)=>a.timestamp-b.timestamp)[0];
 if(paint?.payload?.lcpUrl)facts.push({title:'LCP 记录指向空态图片',text:paint.payload.lcpUrl.split('/').pop()+'；largestContentfulPaint='+paint.payload.largestContentfulPaint+' ms。该渲染记录不能解释请求为何超时。',evidenceIds:[paint.id]});
 if(server.length)facts.push({title:'同 Trace 服务端 Span '+server.length+' 条',text:server.slice(0,3).map(s=>s.title+'：'+s.durationMs+' ms').join('；')+'。链路中的各 Span 不能直接相加当作请求总耗时。',evidenceIds:server.slice(0,3).map(s=>s.id)});
 const gaps=[];
 if(metrics){facts.unshift({title:'原生客户端实测 '+metrics.callDuration+' ms',text:'同 Trace、接口与方法匹配。NetworkTotalMetrics.callDuration='+metrics.callDuration+' ms；APM 的 duration 原值保留。',evidenceIds:[metricsRecord.id]});if(phase.hasResponse===0)facts.unshift({title:'客户端记录未收到 HTTP 响应',text:'httpCode='+metrics.httpCode+'、hasResponse=0、receiveBytesTotal='+metrics.receiveBytesTotal+'，errorCode='+metrics.errorCode+'。这是客户端观测，不能证明服务端未处理。',evidenceIds:[metricsRecord.id]});if(phase.requestStart>phase.firstInterceptorStart&&phase.firstInterceptorStart>0){facts.unshift({title:'客户端两个阶段字段间隔 '+(phase.requestStart-phase.firstInterceptorStart)+' ms',text:'同一 httpTrace 的 firstInterceptorStart → requestStart。尚未确认期间的内部原因，不将该字段差直接命名为排队或网络耗时。',evidenceIds:[metricsRecord.id]});gaps.push({title:'客户端早期阶段的等待原因待核对',text:'结合该版本网络栈的阶段定义、拦截器、调度及连接复用记录，解释 firstInterceptorStart 至 requestStart 的间隔。'});}}
 if(gateway.some(g=>g.payload?.response_status===200)&&failed)gaps.push({title:phase?.hasResponse===0?'网关 200 与客户端未收响应之间仍有缺口':'网关已返回 200，客户端响应到达仍待核对',text:phase?.hasResponse===0?'已取得客户端未收到响应的指标，仍需核对响应传输与连接记录。不同端起点独立，不能用客户端耗时减去网关耗时来归因。':'采集客户端网络层响应到达、取消请求、回调入队和执行时间，区分响应未到达与回调未执行。网关 200 不能证明客户端已收到响应。'});
 if(gateway.some(g=>g.payload?.response_status===499))gaps.push({title:'提前断连原因仍待定位',text:'核对客户端取消/超时记录及接入层连接关闭日志，确认断连发生在哪一侧、何时触发。499 本身不证明具体取消原因。'});
 if(i.durationMs==null)gaps.push({title:metrics?'APM 耗时字段仍需修正':'请求实测耗时未有效上报',text:metrics?'原生日志已提供实测耗时，APM duration=0 的采集缺口仍保留；不能将阈值改写为实测值。':'补充网络层请求起止计时；不能把 timeout 阈值或 duration=0 当作实测耗时。'});
 if(!gateway.length)gaps.push({title:data.downstream.gatewayQuerySuccess?'网关精确查询未命中':'网关证据尚未取得',text:data.downstream.gatewayQuerySuccess?'指定域名 + 本次 Trace，在请求前后五分钟窗口内返回 0 条。未命中不等于请求未到网关。':'查询未成功或尚未执行，不把查询失败当作空结果。'});
 if(data.downstream.spanCount===0&&data.downstream.traceQuerySuccess)gaps.push({title:'XRAY 未返回可用 Span',text:'该 Trace 的 analyzed_spans 返回 null / 空。可能涉及采样或上报缺口，不能推断服务端正常或异常。'});
 else if(!server.length)gaps.push({title:'服务端处理耗时仍未取得',text:'当前证据没有服务端 Span，网关耗时不能代替业务服务处理耗时。'});
 if(!i.environment||!data.target.bundle)gaps.push({title:'运行泳道与验证目标待核对',text:'源数据未提供泳道或待验证版本。prod 是查询环境，不代表该请求的实际泳道；缓存字段也不代表已清缓存。'});
 if(js)gaps.push({title:'JS 错误未携带请求标识',text:'同会话、相邻时刻与相同错误文案仅提供候选因果关系；需要将 Trace / Request ID 透传到 JS 错误。'});
 if(paint?.payload?.firstContentfulPaint<0)gaps.push({title:'渲染计时存在异常值',text:'firstContentfulPaint 为负值，未用于性能结论；需要核对采集口径与计时原点。'});
 if(data.clientSalvage){const s=data.clientSalvage;const task=records.find(r=>r.type==='salvage-task');if(task)facts.push({title:'已核对客户端回捞任务 '+s.taskId,text:(s.statusLabel||'已取得任务状态')+'；任务与日志覆盖分开核验，不作为取消原因证明。',evidenceIds:[task.id]});for(const gap of s.gaps||[])gaps.push(typeof gap==='string'?{title:'客户端日志证据缺口',text:gap}:gap);}
 if(reviewed){facts.unshift(...review.facts.filter(f=>f.evidenceIds.every(id=>records.some(r=>r.id===id))));gaps.unshift({title:review.boundary.title,text:review.boundary.text+' 下一步：'+review.boundary.nextAction+'。'});}
 const correction=data.metricResolution;
 // A business report explains the metric scope; it must never mark native timeout hypotheses as proven.
 const metricResolution=correction?.kind==='user-confirmed-metric-correction'&&correction.binding?.application==='circles'&&Array.isArray(correction.binding.traceIds)&&correction.binding.traceIds.includes(i.traceId)&&correction.binding.error===i.error&&Array.isArray(correction.binding.incidents)&&correction.binding.incidents.some(expected=>['traceId','timestamp','bundle','endpoint','method'].every(key=>expected[key]===i[key]))&&records.some(r=>r.id===correction.recordId&&r.source==='business'&&r.type==='investigation-context')?correction:null;
 const history=reviewed&&review.history?.kind==='retrospective'&&Array.isArray(review.history.rounds)?review.history:null;
 const roles={anchor:anchor.id,gateway:gateway[0]?.id,native:metricsRecord?.id,'review-native':review?.nativeEvidenceId,'review-context':review?.contextEvidenceId,'review-boundary':review?.boundaryEvidenceId};
 let investigationHistory=history?{...history,rounds:history.rounds.filter(round=>round&&typeof round.id==='string'&&Array.isArray(round.queries)&&Array.isArray(round.evidenceRoles)).map(round=>{
  const queries=round.queries.filter(q=>typeof q.id==='string'&&typeof q.title==='string'&&typeof q.tool==='string'&&typeof q.queriedAt==='string'&&Number.isFinite(Date.parse(q.queriedAt))).slice().sort((a,b)=>Date.parse(a.queriedAt)-Date.parse(b.queriedAt));
  return {...round,queries,startedAt:queries[0]?.queriedAt||null,lastQueryAt:queries[queries.length-1]?.queriedAt||null,evidenceIds:round.evidenceRoles.map(role=>roles[role]).filter(id=>id&&records.some(r=>r.id===id))};
 })}:null;
 if(metricResolution){
  investigationHistory=investigationHistory||{kind:'retrospective',title:'排查与处理记录',rounds:[]};
  investigationHistory.description='工具排查按真实取证记录回溯整理；最新业务确认单独注明来源和反馈日期，不作为工具查询或过滤后效果验证。';
  investigationHistory.rounds.push({id:'metric-correction',title:'业务确认指标口径，相关上报已过滤',summary:'将指标放大原因与单次网络超时分开',finding:metricResolution.summary,conclusion:metricResolution.title,change:'调查目标收敛为 JS 异常指标偏高。历史网络请求证据保留，不能据此解释指标总量。',remaining:metricResolution.nextDetail,evidenceIds:[metricResolution.recordId],queries:[],sourceKind:'business-feedback',reportedOn:metricResolution.reportedOn,originalFeedback:metricResolution.originalFeedback});
 }
 const verdict=checks.some(c=>c.status==='fail')?'conditions':gateway.length?'associated':'insufficient';
 return {data,records,matched,contexts,excluded,candidates,checks,facts,gaps,gateway,server,anchor,failed,verdict,nativeStages,review:reviewed?review:null,investigationHistory,metricResolution};
}
function report(r){
 const d=r.data,i=d.incident;
 const metricSection=r.metricResolution?['','## 当前主结论 · JS 指标口径修正',r.metricResolution.title,r.metricResolution.summary,'来源：'+r.metricResolution.sourceLabel+'；反馈日期：'+r.metricResolution.reportedOn,'处理状态：业务反馈已过滤；生效时间未提供，过滤后趋势尚未验证。','适用范围：'+r.metricResolution.scope,'下一步：'+r.metricResolution.nextAction+'。'+r.metricResolution.nextDetail,'证据入口：'+r.metricResolution.recordId]:[];
 const historySection=r.investigationHistory?['','## 排查历史 · 历史排查回溯',r.investigationHistory.description,...r.investigationHistory.rounds.flatMap((round,n)=>['','### 第 '+(n+1)+' 轮 · '+round.title,round.sourceKind==='business-feedback'?'业务反馈日期：'+round.reportedOn+'（生效时间未提供）':'取证记录时间：'+(round.startedAt||'未提供')+' 至 '+(round.lastQueryAt||'未提供'),'新增发现：'+round.finding,'阶段判断（回溯整理）：'+round.conclusion,'判断推进：'+round.change,'仍待解决：'+round.remaining,'证据入口：'+round.evidenceIds.join(', '),...round.queries.map(q=>'- 历史取证 '+q.id+' · '+q.title+' · '+q.queriedAt+' · '+(q.success?'已执行':'查询失败')+' · SHA-256 '+q.responseSha256)])]:[];
 const reviewSection=r.review?['',r.metricResolution?'## 历史单次请求复核（网络根因未确认）':'## 留存复核与当前定位','复核时间：'+r.review.reviewedAt,'状态：阶段已定位；根因待补证（未确认用户网络差、QUIC回退或取消失效）',...(r.nativeStages?['原生fetchStart至requestStart：'+r.nativeStages.beforeSendMs+' ms；发送阶段：'+r.nativeStages.sendMs+' ms；发送后至结束：'+r.nativeStages.afterSendMs+' ms。','原生日志callDuration='+r.nativeStages.callDurationMs+' ms；时间戳起止差='+r.nativeStages.timestampDurationMs+' ms，原值分别保留。']:[]),'### 待验证方向',...r.review.hypotheses.map(h=>'- ['+h.state+'] '+h.title+'：'+h.text+' ['+h.evidenceIds.join(', ')+']'),'### 取证边界',r.review.boundary.text,'下一步：'+r.review.boundary.nextAction,...r.review.boundary.requiredEvidence.map(x=>'- '+x),'复核范围：'+r.review.scope]:[];
 return ['# 迹线 Trace — 真实异常证据报告','','样本：'+i.id,'异常：'+i.title,'数据来源：'+(['real-snapshot','real-query'].includes(d.provenance)?'官方 CLI 真实采集结果（已脱敏）':'用户导入文件；未核验来源'),'采集时间：'+(d.collection.capturedAt||'未提供'),...(d.collection.timeResolution?['时间定位：'+d.collection.timeResolution.description,...d.collection.timeResolution.searchedWindows.map(w=>'实际检索窗口：'+w.start+' 至 '+w.end+'；返回 '+w.returnedCount+' 条；'+w.queryId)]:[]),'Trace ID：'+(i.traceId||'缺失'),'原平台：'+(d.collection.sourceUrl||'未提供'),...metricSection,...reviewSection,...historySection,'','## 已确认事实',...r.facts.map(f=>'- '+f.title+'。'+f.text+' ['+f.evidenceIds.join(', ')+']'),'','## 关联依据',...r.records.map(e=>'- ['+({matched:'请求证据',context:'上下文',candidate:'待确认',excluded:'已排除'}[e.status])+'] '+e.id+' '+e.title+'：'+e.basis),'','## 证据缺口与下一步',...r.gaps.map(g=>'- '+g.title+'：'+g.text),'',...(d.clientSalvage?['## 客户端回捞','任务：'+(d.clientSalvage.taskId||'未创建'),'实际状态：'+d.clientSalvage.statusLabel,'覆盖范围：'+d.clientSalvage.coverage?.description,'关联依据：'+d.clientSalvage.associationBasis,...(d.clientSalvage.excerpts||[]).map(x=>'- '+x.file+':'+x.lineStart+' '+x.text)]:[]),'','## 查询审计',...d.queries.map(q=>'- '+q.id+' '+q.title+'；'+q.queriedAt+'；exit='+q.exitCode+'；记录数='+(q.returnedCount??'未知')+'；响应 SHA-256='+q.responseSha256),'','## 判断边界','- 本报告对应明确的一次采集时刻；在线查询结果与预置快照分别标注。','- Trace 一致、会话一致和请求级精确关联是不同证据范围。','- 查询未命中不能证明请求没到服务端，查询失败也不等于空结果。','- 超时阈值不是实测耗时；不同端的耗时不相减后直接归因网络。','- 未取得请求与服务端阶段证据前，不确认根因或宣称修复有效。','','## 原始证据快照','```json',JSON.stringify(d,null,2),'```',''].join('\n');
}
const api={validate,analyze,match,report,copy,sourceNames,traceValid};
if(typeof module!=='undefined'&&module.exports)module.exports=api;else root.TraceEngine=api;
})(typeof globalThis!=='undefined'?globalThis:this);
