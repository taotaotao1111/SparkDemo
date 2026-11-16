"""Regression tests for timezone windows and bounded rate-limit recovery."""
import argparse
import datetime as dt
import subprocess
import unittest
from unittest.mock import patch
import app
from scripts.collect_evidence import Collector


class PipelineRegressionTests(unittest.TestCase):
    def test_trace_only_uses_known_time_but_queries_fresh_data(self):
        seen=[]
        trace='d0cfa9324c81156b1c6eb03425f916c7'
        row={'userId':'private','timestamp':1793674344492,'time':'2026-11-03 10:52:24.492','data':{'traceId':trace}}
        def query(collector,tool,args,title,scope,**kwargs):
            seen.append(args)
            audit={'id':'Q-01','success':True};collector.audit.append(audit)
            return {'logs':[row],'coveredFullRange':True},audit
        with patch.object(app,'tool_path',return_value='/bin/true'),patch.object(Collector,'query',query):
            result=app.search_work(app.LEGACY_AUTH_EMAIL,app.SearchBody(sample=trace),lambda title:None)
        self.assertEqual(len(seen),1)
        self.assertEqual(result['candidates'][0]['traceId'],trace)
        self.assertEqual(result['timeResolution']['mode'],'known-sample-time')
        self.assertIn('measurement_data.traceId='+trace,seen[0])
        self.assertEqual(seen[0][seen[0].index('--st')+1],str(row['timestamp']-300000))
        ticket=app.TICKETS.pop(result['candidates'][0]['selectionToken'])
        self.assertEqual(ticket['audits'][0]['id'],'Q-01')

    def test_unknown_trace_stops_at_match_and_keeps_previous_empty_query(self):
        trace='1234567890abcdef1234567890abcdef';seen=[]
        row={'userId':'private','timestamp':1793674344492,'data':{'traceId':trace}}
        def query(collector,tool,args,title,scope,**kwargs):
            seen.append(args);audit={'id':f'Q-{len(seen):02}','success':True};collector.audit.append(audit)
            return {'logs':[row] if len(seen)==2 else [],'coveredFullRange':True},audit
        with patch.object(app,'tool_path',return_value='/bin/true'),patch.object(Collector,'query',query):
            result=app.search_work(app.LEGACY_AUTH_EMAIL,app.SearchBody(sample=trace),lambda title:None)
        self.assertEqual(len(seen),2)
        self.assertEqual(len(result['timeResolution']['searchedWindows']),2)
        ticket=app.TICKETS.pop(result['candidates'][0]['selectionToken'])
        self.assertEqual(len(ticket['audits']),2)
        for args in seen:
            self.assertEqual(int(args[args.index('--et')+1])-int(args[args.index('--st')+1]),86400000)

    def test_unknown_trace_search_is_bounded_without_guessing_date(self):
        now=dt.datetime(2026,11,4,18,tzinfo=app.ZONE)
        windows,mode,_=app.search_windows('1234567890abcdef1234567890abcdef',None,now)
        self.assertEqual(mode,'recent-seven-days')
        self.assertEqual(len(windows),7)
        self.assertEqual(windows[0][1],now)
        self.assertEqual(windows[-1][0],now-dt.timedelta(days=7))
        self.assertTrue(all((end-start)==dt.timedelta(days=1) for start,end in windows))

    def test_apm_window_is_unix_milliseconds(self):
        seen = []
        def query(self, tool, args, title, scope, **kwargs):
            seen.append(args)
            return {'logs': [], 'coveredFullRange': True}, {'id': 'Q-01'}
        with patch.object(app, 'tool_path', return_value='/bin/true'), patch.object(Collector, 'query', query):
            app.search_work(app.LEGACY_AUTH_EMAIL, app.SearchBody(sample='d0cfa8c0160fd956a28a674778396feb', occurredAt='2026-11-03T10:51:26'), lambda title: None)
        args = seen[0]
        self.assertEqual(args[args.index('--st') + 1], '1793673986000')
        self.assertEqual(args[args.index('--et') + 1], '1793674586000')

    def test_cli_display_timezone_is_explicit(self):
        self.assertEqual(app.process_env()['TZ'], 'Asia/Shanghai')

    def test_rate_limit_waits_and_keeps_both_attempts(self):
        c = Collector(argparse.Namespace(), apm='/bin/true', xray='/bin/true')
        failed = subprocess.CompletedProcess([], 1, '', '错误: HTTP 429 rate limit exceeded')
        success = subprocess.CompletedProcess([], 0, '{"count":1,"logs":[]}', '')
        with patch('scripts.collect_evidence.subprocess.run', side_effect=[failed, success]), patch('scripts.collect_evidence.time.sleep') as sleep:
            result, audit = c.query('xray', ['log', 'query'], '网关查询', {})
        self.assertEqual(result['count'], 1)
        self.assertEqual(len(c.audit), 2)
        self.assertFalse(c.audit[0]['success'])
        self.assertTrue(audit['success'])
        self.assertTrue(any(call.args == (61,) for call in sleep.call_args_list))

    def test_second_rate_limit_does_not_loop(self):
        c = Collector(argparse.Namespace(), apm='/bin/true', xray='/bin/true')
        failed = subprocess.CompletedProcess([], 1, '', '错误: HTTP 429 rate limit exceeded')
        with patch('scripts.collect_evidence.subprocess.run', return_value=failed) as run, patch('scripts.collect_evidence.time.sleep'):
            result, audit = c.query('xray', ['log', 'query'], '网关查询', {})
        self.assertEqual(run.call_count, 2)
        self.assertIsNone(result)
        self.assertFalse(audit['success'])

    def test_authentication_failure_is_not_retried(self):
        c = Collector(argparse.Namespace(), apm='/bin/true', xray='/bin/true')
        failed = subprocess.CompletedProcess([], 3, '{"success":false,"error":{"code":"AUTHENTICATION_FAILED","message":"login required"}}', '')
        with patch('scripts.collect_evidence.subprocess.run', return_value=failed) as run, patch('scripts.collect_evidence.time.sleep'):
            with self.assertRaises(RuntimeError):
                c.query('apm', ['log', 'search'], '定位样本', {})
        self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
