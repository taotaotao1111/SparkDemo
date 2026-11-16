import unittest

import trace_agent as a


class WhitePolicyTests(unittest.TestCase):
    def evidence(self,description):
        return {'id':'E-003','tool':'apm.measurement','success':True,
                'scope':{'app':'circles','name':'hybridWhiteScreen'},
                'result':{'fields':[{'name':'type','mapping':'i1','description':description},
                                    {'name':'nodeCheck','mapping':'i7','description':'0：不符合白屏，1：符合白屏检查'}]}}

    def test_real_metadata_does_not_define_type_enums(self):
        result=a.white_screen_policy([self.evidence('描述')])
        self.assertEqual(result['typeMappingStatus'],'unverified')
        self.assertFalse(result['priorityTypeCodes']);self.assertEqual(result['evidenceIds'],['E-003'])

    def test_type_numbers_are_not_guessed_from_enum_list_or_ratio(self):
        result=a.white_screen_policy([self.evidence('枚举 0 / 1 / 2 / 3，ratio=100')])
        self.assertEqual(result['typeDefinitions'],{});self.assertFalse(result['priorityTypeCodes'])

    def test_explicit_definition_is_used_without_assuming_fixed_codes(self):
        result=a.white_screen_policy([self.evidence('7：完全白屏；9：纯色白屏；5：区域白屏')])
        self.assertEqual(result['typeMappingStatus'],'verified')
        self.assertEqual(result['priorityTypeCodes'],['7','9'])
        self.assertEqual(result['typeDefinitions']['5'],'区域白屏')
        self.assertIn('实际筛选条件',result['statisticsScope'])

    def test_failed_or_conflicting_definitions_do_not_enable_filtering(self):
        failed={**self.evidence('7：完全白屏；9：纯色白屏'),'success':False}
        for evidence in [[failed],[self.evidence('1：完全白屏；1：纯色白屏')]]:
            self.assertFalse(a.white_screen_policy(evidence)['priorityTypeCodes'])

    def test_newer_incomplete_definition_does_not_reuse_old_mapping(self):
        old=self.evidence('7：完全白屏；9：纯色白屏')
        latest={**self.evidence('描述'),'id':'E-020'}
        result=a.white_screen_policy([old,latest])
        self.assertEqual(result['typeMappingStatus'],'unverified');self.assertEqual(result['evidenceIds'],['E-020'])

    def test_planner_receives_policy_when_old_definition_leaves_recent_context(self):
        seen=[]
        thread={'id':'a'*32,'evidence':[self.evidence('描述')]+[{'id':'E-'+str(i),'tool':'apm.logs','success':True} for i in range(4,14)]}
        def model(context):seen.append(context);return {'type':'finish','title':'枚举尚未核实','summary':'保留整体统计口径'}
        a.run(thread,{},'优先排查完全白屏和异常纯色屏',lambda p:object(),lambda *args:None,lambda *args:None,model=model)
        self.assertEqual(seen[0]['whiteScreenPolicy']['evidenceIds'],['E-003'])
        self.assertFalse(seen[0]['whiteScreenPolicy']['priorityTypeCodes'])


if __name__=='__main__':unittest.main()
