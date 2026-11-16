"""A retained review must never migrate to another request or another log file."""
import copy
import json
from pathlib import Path
import unittest

from scripts.case_review import attach_review


ROOT=Path(__file__).resolve().parents[1]


class CaseReviewTests(unittest.TestCase):
    def setUp(self):
        self.path=ROOT/'assets'/'timeout-review.json'
        self.review=json.loads(self.path.read_text())
        binding=self.review['binding']
        self.case={'key':'test','data':{'incident':{k:binding[k] for k in ['traceId','timestamp','bundle','endpoint','method']},'records':[{'id':'NATIVE-ORIGINAL','type':'client-log','traceId':binding['traceId'],'payload':{'fileSha256':binding['nativeFileSha256'],'networkMetrics':{'requestCallEndTimestamp':binding['nativeEndTimestamp']}}}],'queries':[],'collection':{'capturedAt':'original-acquisition-time'}}}

    def test_original_hash_and_incident_allow_idempotent_review(self):
        attach_review(self.case,self.path)
        first=copy.deepcopy(self.case)
        attach_review(self.case,self.path)
        self.assertEqual(self.case,first)
        self.assertFalse(self.case['data']['evidenceReview']['rootCauseConfirmed'])
        self.assertEqual(self.case['data']['collection']['capturedAt'],'original-acquisition-time')
        self.assertEqual(self.case['data']['evidenceReview']['sourceRecordIds'],['NATIVE-ORIGINAL'])

    def test_trace_version_time_and_endpoint_mismatches_never_attach(self):
        for key,value in [('traceId','a'*32),('timestamp',1),('bundle','circles@other'),('endpoint','/another'),('method','POST')]:
            with self.subTest(key=key):
                case=copy.deepcopy(self.case);case['data']['incident'][key]=value
                attach_review(case,self.path)
                self.assertNotIn('evidenceReview',case['data'])

    def test_same_trace_without_original_source_is_insufficient(self):
        for mode in ['hash','end','no-metrics']:
            case=copy.deepcopy(self.case);payload=case['data']['records'][0]['payload']
            if mode=='hash':payload['fileSha256']='another-file'
            elif mode=='end':payload['networkMetrics']['requestCallEndTimestamp']=1
            else:payload.pop('networkMetrics')
            attach_review(case,self.path)
            self.assertNotIn('evidenceReview',case['data'])

    def test_independent_context_never_inherits_incident_trace(self):
        attach_review(self.case,self.path)
        context=[r for r in self.case['data']['records'] if r.get('type')=='investigation-context']
        self.assertEqual(len(context),2)
        self.assertTrue(all(not r['traceId'] for r in context))
        self.assertTrue(any(not q['success'] for q in self.case['data']['queries']))


if __name__=='__main__':unittest.main()
