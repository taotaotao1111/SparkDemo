import json
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
import app
from scripts.vesta_evidence import VestaEvidence,attach


class VestaTests(unittest.TestCase):
    def row(self):
        return {'userId':'private-user','platform':'iOS','timestamp':1793674344492,'data':{'traceId':'d0cfa9324c81156b1c6eb03425f916c7'}}

    def adapter(self):
        return VestaEvidence('/bin/true',{},'common-internal-access-token-prod=private-cookie','owner@example.com',lambda title:None)

    def test_natural_language_extracts_one_trace(self):
        trace=self.row()['data']['traceId']
        parsed=app.parse_search(app.SearchBody(sample='圈子首页超时，帮我查这条请求\nTrace ID: '+trace,question='为什么超时'))
        self.assertEqual(parsed[1],trace)
        self.assertIsNone(parsed[2])

    def test_multiple_traces_require_selection(self):
        with self.assertRaises(app.HTTPException):
            app.parse_search(app.SearchBody(sample='比较 '+self.row()['data']['traceId']+' 和 '+'a'*32))

    def test_pending_task_is_not_log_evidence_and_refresh_does_not_create(self):
        adapter=self.adapter();row=self.row()
        task={'id':4621951,'state':1,'hasLog':False,'clientLogCount':0,'userId':row['userId'],'platform':'ios','token':'PRIVATE-TASK-TOKEN','deviceId':'PRIVATE-DEVICE'}
        result=SimpleNamespace(stdout=json.dumps(task),stderr='',returncode=0)
        with patch('scripts.vesta_evidence.subprocess.run',return_value=result) as run:
            packet=adapter.collect(row,{'taskId':'4621951'})
        self.assertEqual(run.call_count,1)
        self.assertEqual(packet['status'],'pending')
        self.assertEqual(packet['excerpts'],[])
        self.assertIsNone(packet['coverage']['coversIncident'])
        self.assertNotIn('PRIVATE-TASK-TOKEN',json.dumps(packet))
        self.assertNotIn('private-user',json.dumps(packet))
        self.assertNotIn('PRIVATE-DEVICE',json.dumps(packet))
        self.assertTrue(packet['queries'][0]['success'])

    def test_mismatched_target_is_not_downloaded_or_recreated(self):
        adapter=self.adapter()
        response=SimpleNamespace(stdout=json.dumps({'id':4621951,'state':1,'hasLog':True,'userId':'other-user','platform':'ios'}),stderr='',returncode=0)
        with patch('scripts.vesta_evidence.subprocess.run',return_value=response) as run:
            packet=adapter.collect(self.row(),{'taskId':'4621951'})
        self.assertEqual(packet['status'],'target-mismatch')
        self.assertEqual(run.call_count,1)

    def test_query_failure_does_not_create_task(self):
        response=SimpleNamespace(stdout='',stderr='权限不足',returncode=1)
        with patch('scripts.vesta_evidence.subprocess.run',return_value=response) as run:
            packet=self.adapter().collect(self.row())
        self.assertEqual(packet['status'],'query-failed')
        self.assertEqual(run.call_count,1)
        self.assertFalse(packet['queries'][0]['success'])

    def test_missing_sso_does_not_use_snapshot_as_live_result(self):
        with patch('scripts.vesta_evidence.subprocess.run') as run:
            packet=VestaEvidence('/bin/true',{},'','owner@example.com',lambda title:None).collect(self.row(),{'taskId':'4621951'})
        self.assertEqual(packet['status'],'authentication-required')
        self.assertEqual(packet['queries'],[])
        run.assert_not_called()

    def test_cookie_filter_passes_only_official_sso(self):
        request=SimpleNamespace(headers={'cookie':'other-secret=x; common-internal-access-token-prod=official; another=y'})
        self.assertEqual(app.vesta_cookie(request),'common-internal-access-token-prod=official')

    def test_download_metrics_are_allowlisted_and_files_counted_separately(self):
        row=self.row();trace=row['data']['traceId'];row['data'].update(url='https://example.com/api/base?private=secret',method='GET')
        metrics={'callDuration':5096,'errorCode':-1001,'httpCode':0,'requestCallEndTimestamp':row['timestamp']-5,'receiveBytesTotal':0,'userId':'PRIVATE-USER','httpTraces':[{'xrayTraceId':trace,'path':'/api/base','method':'GET','hasResponse':0,'query':'PRIVATE-QUERY','remoteIp':'10.1.2.3','firstInterceptorStart':row['timestamp']-5100,'requestStart':row['timestamp']-500}]}
        packet={'excerpts':[],'coverage':{},'task':{'clientLogCount':60}}
        with tempfile.TemporaryDirectory() as folder:
            Path(folder,'a.log').write_text('11-03 10:52:24.492 INFRA-NetworkTotalMetrics: '+json.dumps(metrics)+'\n')
            Path(folder,'b.log').write_text('unrelated log\n')
            Path(folder,'download.json').write_text('PRIVATE-DOWNLOAD-URL')
            self.adapter().extract(folder,row,packet)
        self.assertEqual(packet['downloadedFileCount'],2)
        self.assertEqual(packet['task']['clientLogCount'],60)
        self.assertEqual(packet['networkMetrics']['callDuration'],5096)
        self.assertTrue(packet['coverage']['coversIncident'])
        for secret in ['PRIVATE-USER','PRIVATE-QUERY','10.1.2.3','PRIVATE-DOWNLOAD-URL']:
            self.assertNotIn(secret,json.dumps(packet))

    def test_other_endpoint_metrics_do_not_explain_incident(self):
        row=self.row();row['data'].update(url='https://example.com/api/base',method='GET')
        metrics={'callDuration':999,'httpTraces':[{'xrayTraceId':row['data']['traceId'],'path':'/other','method':'GET'}]}
        packet={'excerpts':[],'coverage':{}}
        with tempfile.TemporaryDirectory() as folder:
            Path(folder,'a.log').write_text('INFRA-NetworkTotalMetrics: '+json.dumps(metrics))
            self.adapter().extract(folder,row,packet)
        self.assertNotIn('networkMetrics',packet)
        self.assertEqual(packet['status'],'downloaded-unmatched')

    def test_context_excerpt_never_inherits_incident_trace(self):
        case={'data':{'incident':{'traceId':self.row()['data']['traceId']},'records':[],'queries':[],'collection':{}}}
        attach(case,{'taskId':'1','excerpts':[{'text':'time nearby only'}]})
        record=next(r for r in case['data']['records'] if r['type']=='client-log')
        self.assertEqual(record['traceId'],'')

if __name__=='__main__':unittest.main()
