import datetime as dt
import unittest
from unittest.mock import patch

import trace_agent as a


class MetricRangeTests(unittest.TestCase):
    def runner(self,responses):
        class Runner(a.ToolRunner):
            def execute(self,name,args):
                if name!='apm.metric':return super().execute(name,args)
                self.commands.append(args.copy());self.last_meta={'executed':True,'command':['apm-cli','metric','query'],'exitCode':0}
                item=self.responses.pop(0)
                if isinstance(item,Exception):raise item
                return item,'source-response-hash'
        runner=Runner('test@xiaohongshu.com',{},'/official/apm','/official/xray',lambda *args:{'connected':True},'',a.Privacy(),lambda text:None)
        runner.metric_defs[('circles','jsErrorCount')]={'supportedFilters':['context_platform','measurement_data.errorType']}
        runner.responses=list(responses);runner.commands=[]
        return runner

    def result(self,value):return {'mode':'summary','series':[{'groupBy':{'context_platform':'iOS'},'value':value}]}
    def args(self):return {'app':'circles','name':'jsErrorCount','start':'2026-11-01T00:00:00+08:00','end':'2026-11-04T00:00:00+08:00','groupBy':['context_platform']}

    def test_three_days_are_contiguous_bounded_and_added_by_code(self):
        runner=self.runner([self.result(1),self.result(2),self.result(3)])
        with patch.object(a.time,'sleep'):result,digest=runner.execute('apm.metric_range',self.args())
        self.assertEqual(result['totalCount'],6);self.assertTrue(result['coverage']['complete']);self.assertEqual(result['series'][0]['percentage'],100)
        self.assertEqual(len(runner.commands),3)
        self.assertEqual(runner.commands[0]['end'],runner.commands[1]['start'])
        for command in runner.commands:
            self.assertLessEqual(dt.datetime.fromisoformat(command['end'])-dt.datetime.fromisoformat(command['start']),dt.timedelta(hours=24))
            self.assertEqual(command['limit'],200)
        self.assertEqual(len(runner.last_meta['subqueries']),3);self.assertTrue(digest)

    def test_failure_is_partial_and_never_treated_as_zero_or_full_percent(self):
        runner=self.runner([self.result(1),ValueError('provider unavailable'),self.result(3)])
        with patch.object(a.time,'sleep'):result,_=runner.execute('apm.metric_range',self.args())
        self.assertFalse(result['coverage']['complete']);self.assertEqual(result['coverage']['successfulWindows'],2)
        self.assertEqual(result['observedCount'],4);self.assertNotIn('totalCount',result);self.assertNotIn('percentage',result['series'][0])
        self.assertFalse(result['windows'][1]['success']);self.assertTrue(result['warnings'])

    def test_truncated_groups_do_not_claim_complete_distribution(self):
        data={'mode':'summary','series':[{'groupBy':{'context_platform':'test'+str(i)},'value':1} for i in range(200)]}
        runner=self.runner([data,self.result(2),self.result(3)])
        with patch.object(a.time,'sleep'):result,_=runner.execute('apm.metric_range',self.args())
        self.assertFalse(result['coverage']['complete']);self.assertNotIn('totalCount',result)
        self.assertTrue(all('percentage' not in row for row in result['series']))

    def test_all_failed_windows_do_not_return_successful_evidence(self):
        runner=self.runner([ValueError('provider unavailable')]*3)
        with patch.object(a.time,'sleep'),self.assertRaisesRegex(ValueError,'未取得任何有效分段统计'):runner.execute('apm.metric_range',self.args())
        self.assertEqual(len(runner.last_meta['subqueries']),3)

    def test_rates_and_period_longer_than_fourteen_days_are_rejected(self):
        runner=self.runner([])
        with self.assertRaises(ValueError):runner.execute('apm.metric_range',{**self.args(),'name':'jsErrorRate'})
        with self.assertRaises(ValueError):runner.execute('apm.metric_range',{**self.args(),'end':'2026-11-16T00:00:00+08:00'})
        self.assertFalse(runner.commands)

    def test_unexpected_provider_schema_does_not_discard_other_days(self):
        runner=self.runner([None,self.result(2),self.result(3)])
        with patch.object(a.time,'sleep'):result,_=runner.execute('apm.metric_range',self.args())
        self.assertEqual(result['observedCount'],5);self.assertFalse(result['coverage']['complete'])

    def test_documented_friendly_aliases_use_canonical_provider_fields(self):
        runner=self.runner([self.result(1),self.result(2),self.result(3)])
        with patch.object(a.time,'sleep'):result,_=runner.execute('apm.metric_range',{**self.args(),'groupBy':['platform']})
        self.assertEqual(result['groupBy'],['context_platform'])
        self.assertEqual(runner.commands[0]['groupBy'],['context_platform'])
        with self.assertRaises(ValueError):runner.execute('apm.metric_range',{**self.args(),'groupBy':['platform','context_platform']})

    def test_measurement_contract_has_no_application_flag(self):
        runner=self.runner([])
        source,command=runner.command('apm.measurement',{'app':'circles','name':'infraJsError'})
        self.assertEqual(source,'apm');self.assertEqual(command,['measurement','detail','--name','infraJsError'])

    def test_real_apm_fixture_preserves_both_dimensions(self):
        import json
        from pathlib import Path
        data=json.loads((Path(__file__).parent/'fixtures/apm-joint-group-summary.json').read_text())
        runner=self.runner([data,data,data]);args={**self.args(),'groupBy':['context_platform','measurement_data.errorType']}
        with patch.object(a.time,'sleep'):result,_=runner.execute('apm.metric_range',args)
        self.assertTrue(result['coverage']['complete'])
        self.assertEqual(result['totalCount'],3*sum(row['value'] for row in data['series']))
        _,command=runner.command('apm.metric',{**args,'end':'2026-11-02T00:00:00+08:00'})
        indices=[i for i,value in enumerate(command) if value=='--group-by']
        self.assertEqual([command[i+1] for i in indices],['context_platform','measurement_data.errorType'])
        _,command=runner.command('apm.logs',{'app':'circles','measurements':['httpRequestTiming','infraJsError']})
        indices=[i for i,value in enumerate(command) if value=='--measurement-name']
        self.assertEqual([command[i+1] for i in indices],['httpRequestTiming','infraJsError'])

    def test_empty_series_does_not_prove_zero_errors(self):
        runner=self.runner([{'mode':'summary','series':[]}]*3)
        with patch.object(a.time,'sleep'):result,_=runner.execute('apm.metric_range',self.args())
        self.assertFalse(result['coverage']['complete']);self.assertNotIn('totalCount',result)


if __name__=='__main__':unittest.main()
