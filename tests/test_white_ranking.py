import datetime as dt
import unittest
from unittest.mock import patch

import trace_agent as a


class WhiteRankingTests(unittest.TestCase):
    def runner(self, counts, pvs, rates):
        class Runner(a.ToolRunner):
            def execute(self, name, args):
                if name != 'apm.metric':return super().execute(name,args)
                self.last_meta={'executed':True,'command':['apm-cli',args['name'],args['start']],'exitCode':0}
                values=self.responses[args['name']].pop(0)
                return {'mode':'summary','series':[{'groupBy':{'context_matchedPath':page},'value':value} for page,value in values.items()]},'actual-response-hash'
        runner=Runner('test',{},'/official/apm','/official/xray',lambda *args:{'connected':True},'',a.Privacy(),lambda msg:None)
        runner.responses=dict(zip(['hybridWhiteScreenCount','pageViewCount','hybridWhiteScreenErrorRate'],[counts,pvs,rates]))
        return runner

    def args(self):return {'app':'circles','start':'2026-11-01T00:00:00+08:00','end':'2026-11-03T00:00:00+08:00'}

    def test_rates_are_weighted_and_volume_ranking_is_distinct(self):
        runner=self.runner([{'a':1,'b':5},{'a':1,'b':4}],[{'a':10,'b':100},{'a':20,'b':100}],[{'a':.1,'b':.05},{'a':.05,'b':.04}])
        with patch.object(a.time,'sleep'):result,_=runner.execute('apm.white_screen_ranking',self.args())
        self.assertTrue(result['coverage']['complete'])
        self.assertEqual(result['byRate'][0]['page'],'a');self.assertEqual(result['byCount'][0]['page'],'b')
        self.assertAlmostEqual(result['byRate'][0]['rate'],2/30)
        self.assertNotAlmostEqual(result['byRate'][0]['rate'],.075)
        self.assertEqual(result['byRate'][0]['pageViews'],30)
        self.assertEqual(len(runner.last_meta['subqueries']),6)

    def test_mismatched_denominator_does_not_produce_full_ranking(self):
        runner=self.runner([{'a':1},{'a':2}],[{'a':10},{'a':10}],[{'a':.1},{'a':.3}])
        with patch.object(a.time,'sleep'):result,_=runner.execute('apm.white_screen_ranking',self.args())
        self.assertFalse(result['coverage']['complete']);self.assertEqual(result['byRate'][0]['whiteScreenCount'],1)
        self.assertIn('不一致',result['windows'][-1]['error'])

    def test_unobserved_count_is_not_assumed_zero_for_positive_rate(self):
        runner=self.runner([{'b':1}],[{'a':10,'b':10}],[{'a':.1,'b':.1}])
        args={**self.args(),'end':'2026-11-02T00:00:00+08:00'}
        with patch.object(a.time,'sleep'),self.assertRaisesRegex(ValueError,'未取得'):runner.execute('apm.white_screen_ranking',args)

    def test_future_end_is_clipped_and_request_range_preserved(self):
        runner=self.runner([{'a':1}],[{'a':10}],[{'a':.1}])
        current=dt.datetime.now(a.ZONE)
        args={'app':'circles','start':(current-dt.timedelta(hours=1)).isoformat(),'end':(current+dt.timedelta(days=1)).isoformat()}
        with patch.object(a.time,'sleep'):result,_=runner.execute('apm.white_screen_ranking',args)
        self.assertTrue(result['futureEndClipped']);self.assertEqual(result['requestedRange']['end'],args['end'])
        self.assertLessEqual(dt.datetime.fromisoformat(result['timeRange']['end']),dt.datetime.now(a.ZONE))

    def test_builtin_catalog_is_independent_of_custom_metric_registration(self):
        names={item['name'] for item in a.metric_catalog()}
        self.assertIn('hybridWhiteScreenCount',names);self.assertIn('hybridWhiteScreenErrorRate',names)
        self.assertNotIn('pageWhiteScreenRate',names)
        runner=self.runner([],[],[])
        _,command=runner.command('apm.metric',{'app':'circles','name':'hybridWhiteScreenErrorRate','groupBy':['context_matchedPath']})
        self.assertIn('hybridWhiteScreenErrorRate',command)
        self.assertEqual(runner.metric_defs[('circles','hybridWhiteScreenErrorRate')]['definitionSource'],'official-cli-reference')

    def test_white_counts_are_additive_but_users_and_rates_are_not(self):
        runner=self.runner([],[],[])
        for metric in ['hybridWhiteScreenUserCount','hybridWhiteScreenErrorRate']:
            with self.assertRaises(ValueError):runner.execute('apm.metric_range',{**self.args(),'name':metric,'groupBy':['context_matchedPath']})

    def test_filter_alias_has_explicit_official_command_and_actionable_errors(self):
        import json
        runner=self.runner([],[],[])
        scope={'app':'circles','name':'hybridWhiteScreenCount','groupBy':['context_platform'],
               'filters':{'context_matchedPath':{'method':'in','values':['/circles/circle-square-home']}}}
        _,command=runner.command('apm.metric',scope)
        filters=json.loads(command[command.index('--filters')+1])
        self.assertEqual(filters['context_matchedPath']['method'],'include')
        self.assertEqual(scope['filters']['context_matchedPath']['method'],'in')
        scope['filters']['context_matchedPath']['method']='SQL_EQUALS'
        with self.assertRaisesRegex(ValueError,'请修正 method 参数'):runner.command('apm.metric',scope)

    def test_failed_analysis_preserves_verified_ranking_instead_of_stale_claim(self):
        thread={'id':'a'*32,'report':{'title':'没有白屏指标','generatedAt':'2026-11-16T13:00:00+08:00'},
                'evidence':[{'id':'E-010','success':True,'scope':{},'queriedAt':'2026-11-16T14:00:00+08:00',
                'result':{'mode':'white-screen-ranking','coverage':{'complete':True,'successfulWindows':8},
                'timeRange':{'start':'2026-11-09T00:00:00+08:00','end':'2026-11-16T14:00:00+08:00'}}}]}
        def model(context):raise a.AIServiceError('AI_RESPONSE_TIMEOUT','分析服务未返回')
        result=a.run(thread,{},'继续核查',lambda p:object(),lambda *args:None,lambda *args:None,model=model)
        self.assertTrue(result['interrupted']);self.assertEqual(thread['report']['generatedBy'],'verified-statistics')
        self.assertIn('已查出',thread['report']['title'])
        self.assertEqual(thread['report']['facts'][0]['evidenceIds'],['E-010'])


if __name__=='__main__':unittest.main()
