import copy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import trace_agent as a


class AgentTests(unittest.TestCase):
    def privacy(self):return a.Privacy()
    def runner(self,p=None):
        return a.ToolRunner('tester@xiaohongshu.com',{},'/official/apm','/official/xray',lambda *args:{'connected':True},'',p or self.privacy(),lambda *args:None)

    def test_unrestricted_execution_is_not_a_tool(self):
        for name in ['shell','exec','apm.delete','vesta.salvage']:
            with self.assertRaises(ValueError):self.runner().command(name,{})
        with self.assertRaises(ValueError):self.runner().command('apm.logs',{'app':'circles; touch /tmp/pwn','measurements':['httpRequestTiming']})

    def test_window_bound_and_no_future_query(self):
        with self.assertRaises(ValueError):a.window({'start':'-25h','end':'now'})
        with self.assertRaises(ValueError):a.window({'start':'2027-01-01','end':'2027-01-02'})
        self.assertIn('+08:00',a.window({'start':'-5m'})[0])

    def test_identity_refs_are_opaque_and_owner_data_not_exported(self):
        p=self.privacy();uid='6355fa390000000018029e4e';sid='SESSION-PRIVATE-123'
        raw={'userId':uid,'sessionId':sid,'deviceId':'private-device','cookie':'private-cookie','data':{'url':'https://edith.xiaohongshu.com/api/x?uid='+uid,'traceId':'a'*32,'requestBody':{'email':'foo@secret.com'}}}
        safe=p.clean(raw);serialized=json.dumps(safe)
        self.assertNotIn(uid,serialized);self.assertNotIn(sid,serialized);self.assertNotIn('private-cookie',serialized);self.assertNotIn('private-device',serialized)
        self.assertEqual(p.resolve(safe['userRef'],'U'),uid)
        self.assertIn('edith.xiaohongshu.com',p.hosts)
        with self.assertRaises(ValueError):self.runner().command('apm.sessions',{'app':'circles','userRef':safe['userRef']})

    def test_link_scope_is_preserved_without_url_fetch(self):
        result=self.privacy().question('分析 https://tracker.devops.xiaohongshu.com/apm/white-screen-monitor?applicationName=circles&pageRouter=includes__/dialog&startTime=now-4h&endTime=now')
        params=result['apmLinks'][0]['parameters']
        self.assertEqual(params['applicationName'],'circles');self.assertEqual(params['pageRouter'],'includes__/dialog');self.assertEqual(params['startTime'],'now-4h')

    def test_white_distribution_link_keeps_filter_and_view_without_secrets(self):
        parsed=self.privacy().question('https://tracker.devops.xiaohongshu.com/apm/white-screen-monitor?applicationName=circles&whiteScreenLevel=includes__1,2&whiteFrameCurTab=distribution-analysis&frameGroupBy=pageRouter&whiteScreenType=includes__rn&access_token=PRIVATE_VALUE&unknownFilter=UNSHARED')
        scope=parsed['apmLinks'][0];params=scope['parameters']
        self.assertEqual(params['whiteScreenLevel'],'includes__1,2')
        self.assertEqual(params['whiteFrameCurTab'],'distribution-analysis');self.assertEqual(params['frameGroupBy'],'pageRouter')
        self.assertEqual(params['whiteScreenType'],'includes__rn')
        self.assertEqual(scope['unmappedParameterNames'],['unknownFilter'])
        self.assertNotIn('PRIVATE_VALUE',json.dumps(parsed));self.assertNotIn('UNSHARED',json.dumps(parsed))

    def test_metric_requires_observed_definition(self):
        with self.assertRaises(ValueError):self.runner().command('apm.metric',{'app':'circles','name':'unregisteredCustomCount'})

    def test_gateway_requires_observed_domain(self):
        with self.assertRaises(ValueError):self.runner().command('xray.gateway',{'traceId':'a'*32,'host':'invented.example.com'})

    def test_vesta_download_requires_actual_task_lookup(self):
        with self.assertRaises(ValueError):self.runner().command('vesta.inspect',{'taskId':'4621951','traceId':'a'*32})

    def test_failed_query_and_unknown_ids_never_support_facts(self):
        report=a.citation_report({'facts':[{'text':'root cause','evidenceIds':['E-001','E-999']}],'hypotheses':[]},[{'id':'E-001','success':False}])
        self.assertEqual(report['facts'],[]);self.assertEqual(report['status'],'insufficient-evidence');self.assertTrue(report['gaps'])

    def test_missing_scope_asks_without_query_or_required_auth(self):
        queries=[];saved=[];thread={'id':'a'*32}
        runner=SimpleNamespace(execute=lambda *args:queries.append(args))
        result=a.run(thread,{},'帮我查一下出错原因',lambda p:runner,lambda text:None,lambda payload,refs:saved.append(copy.deepcopy(payload)),model=lambda context:{'type':'ask','question':'请补充应用、发生时间和一条日志或监控链接。'})
        self.assertEqual(queries,[]);self.assertEqual(result['thread']['rounds'][0]['status'],'needs-input');self.assertTrue(saved)

    def test_actual_tool_result_drives_following_decision_and_round_persists(self):
        calls=[];contexts=[]
        def model(context):
            contexts.append(copy.deepcopy(context))
            if len(contexts)==1:return {'type':'tool','tool':'apm.logs','args':{'app':'circles','measurements':['infraJsError']},'reason':'查询实际JS错误'}
            return {'type':'finish','title':'取得错误样本','summary':'已找到一条错误，根因待核对。','facts':[{'text':'取得一条错误样本','evidenceIds':['E-001']}],'gaps':['缺少会话下钻']}
        def execute(name,args):
            calls.append(name);return {'logs':[{'userId':'6355fa390000000018029e4e','measurementName':'infraJsError','data':{'errorMessage':'actual error'}}]},'abc123'
        result=a.run({'id':'a'*32},{},'查circles最近错误',lambda p:SimpleNamespace(execute=execute),lambda text:None,lambda *args:None,model=model)
        self.assertEqual(calls,['apm.logs']);self.assertIn('actual error',json.dumps(contexts[1]));self.assertEqual(result['thread']['report']['facts'][0]['evidenceIds'],['E-001']);self.assertNotIn('6355fa390000000018029e4e',json.dumps(result))
        second=a.run(result['thread'],{},'还缺什么？',lambda p:SimpleNamespace(execute=execute),lambda text:None,lambda *args:None,model=lambda context:{'type':'ask','question':'请补充发生时间。'})
        self.assertEqual(len(second['thread']['rounds']),2)

    def test_cli_failure_is_not_empty_evidence(self):
        fake=SimpleNamespace(returncode=4,stdout=json.dumps({'success':False,'error':{'message':'permission denied'}}))
        with patch.object(a.subprocess,'run',return_value=fake):
            with self.assertRaisesRegex(ValueError,'permission denied'):
                self.runner().execute('apm.logs',{'app':'circles','measurements':['infraJsError']})

    def test_ai_provider_business_failure_never_exposes_credentials(self):
        response=SimpleNamespace(status_code=200,json=lambda:{'Code':'denied','Error':'secret'})
        with patch.object(a,'ai_config',return_value={'ai.base_url':'https://official.internal','ai.api_key':'SECRET'}),patch.object(a.httpx,'post',return_value=response):
            with self.assertRaises(RuntimeError) as ctx:a.decide({})
        self.assertNotIn('secret',str(ctx.exception).lower())

    def test_multi_model_key_uses_observed_model_id_only_after_verified_rejection(self):
        denial=SimpleNamespace(status_code=403,text="请求模型 '' 未绑定，已绑定模型: [Claude Opus 5.5 (微软)]",json=lambda:{'message':"请求模型 '' 未绑定"})
        inventory=SimpleNamespace(status_code=200,json=lambda:{'data':[{'id':'test-claude-opus-5-5-model'}]})
        success=SimpleNamespace(status_code=200,json=lambda:{'content':[{'type':'text','text':'{"type":"ask","question":"需要应用和时间。"}'}]})
        with patch.object(a,'ai_config',return_value={'ai.base_url':'https://official.internal','ai.api_key':'SECRET'}),patch.object(a.httpx,'get',return_value=inventory),patch.object(a.httpx,'post',side_effect=[denial,success]) as request:
            result=a.decide({})
        self.assertEqual(result['type'],'ask')
        self.assertEqual(request.call_args.kwargs['json']['model'],'test-claude-opus-5-5-model')

    def test_session_without_id_requires_explicit_small_scope(self):
        p=self.privacy();ref=p.ref('U','12345678');runner=self.runner(p)
        with self.assertRaises(ValueError):runner.command('apm.session',{'app':'circles','userRef':ref,'allSessions':True,'start':'-4h'})
        _,cmd=runner.command('apm.session',{'app':'circles','userRef':ref,'allSessions':True,'start':'-5m'})
        self.assertEqual(cmd[cmd.index('--session-id')+1],'')

    def test_shared_thread_route_never_returns_private_references(self):
        from fastapi.testclient import TestClient
        import app
        import case_store
        headers={'Decrypted-Userinfo':json.dumps({'email':'other@xiaohongshu.com'})}
        with patch.object(case_store,'get_thread',return_value={'thread':{'id':'a'*32},'refs':{'RAW':'PRIVATE'},'canContinue':False}):
            response=TestClient(app.app).get('/api/agent/threads/'+'a'*32,headers=headers)
        self.assertEqual(response.status_code,200)
        self.assertFalse(response.json()['canContinue'])
        self.assertNotIn('PRIVATE',response.text)
        self.assertNotIn('refs',response.json())


if __name__=='__main__':unittest.main()
