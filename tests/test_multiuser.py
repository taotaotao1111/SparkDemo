import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
import app
import case_store
from scripts import xray_profile


class MultiuserTests(unittest.TestCase):
    def setUp(self):
        self.a='first@xiaohongshu.com';self.b='second@xiaohongshu.com'
        self.client=TestClient(app.app)

    def headers(self,email):
        return {'Decrypted-Userinfo':json.dumps({'email':email,'name':email.split('@')[0]}),'X-Trace-Request':'1'}

    def test_company_users_get_their_own_sso_identity(self):
        self.assertEqual(self.client.get('/api/capabilities').status_code,401)
        for email in [self.a,self.b]:
            r=self.client.get('/api/capabilities',headers=self.headers(email))
            self.assertEqual(r.status_code,200)
            self.assertTrue(r.json()['canQuery'])
            self.assertFalse(r.json()['resultsPrivate'])
            self.assertEqual(r.json()['user']['email'],email)

    def test_shared_cases_available_to_another_logged_in_user(self):
        case={'key':'shared-test','data':{'incident':{'traceId':'a'*32}}}
        with patch.object(case_store,'list_cases',return_value=[case]) as read:
            response=self.client.get('/api/cases',headers=self.headers(self.b))
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()['visibility'],'company-shared')
        self.assertEqual(response.json()['cases'][0]['key'],'shared-test')
        read.assert_called_once_with(self.b)

    def test_auth_links_are_only_returned_to_their_owner(self):
        own={'owner':self.a,'state':'pending','url':'https://tracker.devops.xiaohongshu.com/apm/cli-auth?user_code=FIRST-ONLY'}
        with patch.dict(app.AUTH,{(self.a,'apm'):own},clear=True),patch.object(app,'cli_status',return_value={'connected':False,'accountMatches':None}):
            a=self.client.get('/api/connections',headers=self.headers(self.a)).json()
            b=self.client.get('/api/connections',headers=self.headers(self.b)).json()
        self.assertIn('FIRST-ONLY',json.dumps(a))
        self.assertNotIn('FIRST-ONLY',json.dumps(b))
        self.assertEqual(b['authorizations'],{})

    def test_unfinished_jobs_and_selection_tokens_remain_owner_scoped(self):
        with patch.dict(app.JOBS,{'secretjob':{'owner':self.a,'createdAt':time.time(),'state':'complete','result':{'private':'in-progress-context'}}},clear=True):
            self.assertEqual(self.client.get('/api/jobs/secretjob',headers=self.headers(self.b)).status_code,404)
        token='a'*32
        with patch.dict(app.TICKETS,{token:{'owner':self.a,'createdAt':time.time()}},clear=True):
            self.assertEqual(self.client.post('/api/investigate',headers=self.headers(self.b),json={'selectionToken':token}).status_code,404)

    def test_query_credentials_are_isolated_and_must_match_sso(self):
        a=app.process_env(self.a);b=app.process_env(self.b)
        self.assertNotEqual(a['APM_CLI_CONFIG_DIR'],b['APM_CLI_CONFIG_DIR'])
        self.assertNotEqual(a['TRACE_XRAY_PROFILE'],b['TRACE_XRAY_PROFILE'])
        payload={'success':True,'data':{'loggedIn':True,'email':self.a}}
        with patch.object(app,'tool_path',return_value='/bin/true'),patch.object(app.subprocess,'run',return_value=SimpleNamespace(stdout=json.dumps(payload),returncode=0)):
            self.assertFalse(app.cli_status('apm',self.b)['connected'])
            self.assertTrue(app.cli_status('apm',self.a)['connected'])

    def test_shared_view_redacts_input_and_updates_old_private_semantics(self):
        case={'data':{'collection':{'semantics':'only owner'},'investigation':{'question':'timeout uid=123456 token=private-secret'}}}
        shared=case_store.shared_view(case)
        self.assertEqual(shared['data']['collection']['visibility'],'company-shared')
        self.assertNotIn('private-secret',shared['data']['investigation']['question'])
        self.assertEqual(case['data']['collection']['semantics'],'only owner')

    def test_xray_profile_switches_files_without_reading_or_copying_credentials(self):
        # These are synthetic test fixtures under a temporary HOME, not real login files.
        with tempfile.TemporaryDirectory() as folder:
            home=Path(folder);directory=home/'.config'/'xray';directory.mkdir(parents=True)
            auth=directory/'auth.json';auth.write_text('TEST-FIRST')
            first=app.actor_ref(self.a);second=app.actor_ref(self.b)
            def second_cli(*args,**kwargs):
                self.assertFalse(auth.exists())
                auth.write_text('TEST-SECOND')
                return SimpleNamespace(returncode=0)
            env={'TRACE_XRAY_PROFILE':second,'TRACE_XRAY_LEGACY_PROFILE':first}
            with patch.object(Path,'home',return_value=home),patch.dict(os.environ,env),patch.object(sys,'argv',['profile','auth','login']),patch.object(xray_profile.subprocess,'run',side_effect=second_cli):
                self.assertEqual(xray_profile.main(),0)
            self.assertFalse(auth.exists())
            self.assertEqual((directory/'trace-profiles'/first/'auth.json').read_text(),'TEST-FIRST')
            self.assertEqual((directory/'trace-profiles'/second/'auth.json').read_text(),'TEST-SECOND')
            def first_cli(*args,**kwargs):
                self.assertEqual(auth.read_text(),'TEST-FIRST')
                return SimpleNamespace(returncode=0)
            env['TRACE_XRAY_PROFILE']=first
            with patch.object(Path,'home',return_value=home),patch.dict(os.environ,env),patch.object(sys,'argv',['profile','auth','status']),patch.object(xray_profile.subprocess,'run',side_effect=first_cli):
                self.assertEqual(xray_profile.main(),0)
            self.assertFalse(auth.exists())
            self.assertEqual((directory/'trace-profiles'/second/'auth.json').read_text(),'TEST-SECOND')

    def test_shared_storage_query_has_no_owner_filter_and_deduplicates_trace(self):
        class Connection:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def execute(self,query,*params):
                self.query=query;self.params=params;return self
            def fetchall(self):return []
        conn=Connection()
        with patch.object(case_store,'connect',return_value=conn):case_store.list_cases(self.b)
        self.assertIn('DISTINCT ON (trace_id)',conn.query)
        self.assertNotIn('WHERE owner_email',conn.query)

if __name__=='__main__':unittest.main()
