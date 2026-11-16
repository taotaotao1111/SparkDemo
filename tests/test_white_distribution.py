import unittest
from unittest.mock import patch

import trace_agent as a


class DistributionTests(unittest.TestCase):
    def runner(self,responses):
        class Runner(a.ToolRunner):
            def execute(self,name,args):
                if name!='apm.metric':return super().execute(name,args)
                self.calls.append(args);self.last_meta={'executed':True,'command':['official-cli',args['name']]}
                value=self.responses.pop(0)
                if isinstance(value,Exception):raise value
                return {'mode':'summary','series':[{'groupBy':{'context_matchedPath':page},'value':count} for page,count in value.items()]},'source-hash'
        r=Runner('test',{},'/official/apm','/official/xray',lambda *args:{'connected':True},'',a.Privacy(),lambda *args:None)
        r.responses=list(responses);r.calls=[];return r

    def args(self):return {'app':'circles','start':'2026-11-01T00:00:00+08:00','end':'2026-11-03T00:00:00+08:00','levelCodes':['1','2'],'requestedDataMode':'preaggregated'}

    def test_count_share_uses_filtered_count_denominator_and_preserves_modes(self):
        r=self.runner([{'a':10,'b':30},{'a':10,'b':50}])
        with patch.object(a.time,'sleep'):data,_=r.execute('apm.white_screen_distribution',self.args())
        self.assertEqual(data['totalCount'],100);self.assertEqual(data['byCount'][0],{'page':'b','whiteScreenCount':80,'sharePercent':80})
        self.assertEqual(data['requestedDataMode'],'preaggregated');self.assertEqual(data['comparisonStatus'],'not-verified')
        self.assertTrue(data['warnings']);self.assertTrue(data['coverage']['complete'])
        for scope in r.calls:
            self.assertEqual(scope['name'],'hybridWhiteScreenCount')
            self.assertEqual(scope['filters']['measurement_data.i1'],{'method':'include','values':['1','2']})
        self.assertNotIn('pageViews',data['byCount'][0]);self.assertNotIn('ratePercent',data['byCount'][0])

    def test_partial_range_never_has_full_share(self):
        r=self.runner([{'a':3},ValueError('provider unavailable')])
        with patch.object(a.time,'sleep'):data,_=r.execute('apm.white_screen_distribution',self.args())
        self.assertFalse(data['coverage']['complete']);self.assertNotIn('totalCount',data)
        self.assertNotIn('sharePercent',data['series'][0])

    def test_conflicting_or_invented_level_labels_are_rejected(self):
        r=self.runner([])
        for extra in [{'levelCodes':['完全白屏']},{'filters':{'measurement_data.i1':{'method':'include','values':['3']}}}]:
            with self.assertRaises(ValueError):r.execute('apm.white_screen_distribution',{**self.args(),**extra})
        self.assertFalse(r.calls)

    def test_new_filtered_distribution_replaces_stale_unfiltered_narrative(self):
        thread={'report':{'title':'广场首页为主','generatedAt':'2026-11-16T14:00:00+08:00'},'evidence':[
            {'id':'E-018','success':True,'queriedAt':'2026-11-16T15:00:00+08:00',
             'result':{'mode':'white-screen-distribution','coverage':{'complete':True},'levelCodes':['1','2'],
                       'timeRange':{'start':'2026-11-09','end':'2026-11-16'}}}]}
        a.preserve_verified_ranking(thread)
        self.assertIn('预聚合口径待对齐',thread['report']['title'])
        self.assertIn('不适用于本次范围',thread['report']['summary'])
        self.assertEqual(thread['report']['facts'][0]['evidenceIds'],['E-018'])


if __name__=='__main__':unittest.main()
