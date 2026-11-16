import copy
import json
import socket
import ssl
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import trace_agent as a


class AnalysisServiceTests(unittest.TestCase):
    def test_dns_is_classified_without_echoing_provider_or_key(self):
        exc=httpx.ConnectError('secret-provider/path?token=PRIVATE')
        exc.__cause__=socket.gaierror(-2,'Name or service not known')
        failure=a.connection_failure(exc).failure
        self.assertEqual(failure['code'],'AI_DNS_FAILURE')
        self.assertTrue(failure['retryable'])
        self.assertNotIn('PRIVATE',json.dumps(failure))
        self.assertNotIn('secret-provider',json.dumps(failure))

    def test_certificate_failure_is_not_retried_or_downgraded(self):
        error=httpx.ConnectError('CERTIFICATE_VERIFY_FAILED certificate verify failed')
        with patch.object(a.httpx,'post',side_effect=error) as request,patch.object(a.time,'sleep') as sleep:
            with self.assertRaises(a.AIServiceError) as result:a.ai_http('post','https://official.internal',json={})
        self.assertEqual(result.exception.failure['code'],'AI_TLS_CERTIFICATE')
        self.assertFalse(result.exception.failure['retryable'])
        self.assertEqual(request.call_count,1)
        sleep.assert_not_called()
        self.assertNotIn('verify',request.call_args.kwargs)

    def test_transient_connect_error_retries_once_then_succeeds(self):
        expected=SimpleNamespace(status_code=200)
        messages=[]
        with patch.object(a.httpx,'post',side_effect=[httpx.ConnectError('connection refused'),expected]) as request,patch.object(a.time,'sleep'):
            actual=a.ai_http('post','https://official.internal',on_retry=messages.append,json={'test':True})
        self.assertIs(actual,expected);self.assertEqual(request.call_count,2);self.assertEqual(len(messages),1)

    def test_read_timeout_is_not_automatically_replayed(self):
        with patch.object(a.httpx,'post',side_effect=httpx.ReadTimeout('late response')) as request,patch.object(a.time,'sleep') as sleep:
            with self.assertRaises(a.AIServiceError):a.ai_http('post','https://official.internal',json={})
        self.assertEqual(request.call_count,1);sleep.assert_not_called()

    def test_health_uses_supported_model_catalog_path_and_hides_credentials(self):
        with patch.object(a,'ai_config',return_value={'ai.base_url':'https://official.internal','ai.api_key':'PRIVATE'}),patch.object(a.httpx,'get',side_effect=[SimpleNamespace(status_code=404),SimpleNamespace(status_code=200)]):
            result=a.analysis_health()
        self.assertTrue(result['reachable']);self.assertEqual(result['httpStatus'],200);self.assertNotIn('PRIVATE',json.dumps(result))

    def test_interrupted_run_keeps_existing_evidence_and_typed_failure(self):
        thread={'id':'a'*32,'evidence':[{'id':'E-001','success':True,'result':{'count':3}}]}
        saved=[]
        def model(context):raise a.AIServiceError('AI_CONNECT_FAILURE','分析服务暂时无法连接',retryable=True)
        result=a.run(thread,{},'圈子这一周JS错误分布',lambda p:SimpleNamespace(),lambda *args:None,lambda t,refs:saved.append(copy.deepcopy(t)),model=model)
        self.assertEqual(result['thread']['failure']['service'],'analysis')
        self.assertEqual(result['thread']['rounds'][-1]['failure']['code'],'AI_CONNECT_FAILURE')
        self.assertEqual(len(result['thread']['evidence']),1);self.assertTrue(saved)

    def test_builtin_metadata_miss_remains_failed_and_reference_is_explicit(self):
        p=a.Privacy();r=a.ToolRunner('user@xiaohongshu.com',{},'/official/apm','/official/xray',lambda *args:{'connected':True},'',p,lambda *args:None)
        response=SimpleNamespace(returncode=1,stdout=json.dumps({'success':False,'error':{'message':'指标 jsErrorCount（应用 circles） 不存在'}}))
        with patch.object(a.subprocess,'run',return_value=response):
            with self.assertRaisesRegex(ValueError,'本次定义查询未命中'):r.execute('apm.metric_detail',{'app':'circles','name':'jsErrorCount'})
        self.assertEqual(r.last_meta['exitCode'],1)
        self.assertEqual(r.metric_defs[('circles','jsErrorCount')]['definitionSource'],'official-cli-reference')
        source,command=r.command('apm.metric',{'app':'circles','name':'jsErrorCount','groupBy':['context_platform']})
        self.assertEqual(source,'apm');self.assertIn('context_platform',command)

    def test_exhausted_budget_is_typed_and_not_automatically_retried(self):
        response=SimpleNamespace(status_code=402,text='Key budget exhausted',json=lambda:{'message':'Key预算已耗尽'})
        with patch.object(a,'ai_config',return_value={'ai.base_url':'https://official.internal','ai.api_key':'PRIVATE'}),patch.object(a.httpx,'post',return_value=response) as request:
            with self.assertRaises(a.AIServiceError) as result:a.decide({})
        self.assertEqual(result.exception.failure['code'],'AI_BUDGET_EXHAUSTED')
        self.assertFalse(result.exception.failure['retryable']);self.assertEqual(request.call_count,1)
        self.assertNotIn('PRIVATE',str(result.exception))

    def test_unexecuted_prerequisite_failure_can_be_retried_after_setup(self):
        runner=SimpleNamespace(ready=False,last_meta={})
        def execute(name,args):
            runner.last_meta={'executed':False}
            if name=='apm.metric_detail':runner.ready=True;runner.last_meta={'executed':True};return {'configured':True},'meta-hash'
            if not runner.ready:raise ValueError('need definition')
            runner.last_meta={'executed':True};return {'count':3},'metric-hash'
        runner.execute=execute
        args={'app':'circles','name':'jsErrorCount'}
        actions=iter([{'type':'tool','tool':'apm.metric','args':args},{'type':'tool','tool':'apm.metric_detail','args':args},{'type':'tool','tool':'apm.metric','args':args},{'type':'finish','facts':[{'text':'count3','evidenceIds':['E-003']}]}])
        result=a.run({'id':'a'*32},{},'query',lambda p:runner,lambda *args:None,lambda *args:None,model=lambda c:next(actions))
        self.assertTrue(result['thread']['evidence'][-1]['success'])
        self.assertEqual(result['thread']['report']['facts'][0]['evidenceIds'],['E-003'])


if __name__=='__main__':unittest.main()
