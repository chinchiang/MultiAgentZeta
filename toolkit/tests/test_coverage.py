"""The coverage record's numbers: denominator, valid judgements, the effective judgement rate and the rest
(〈定義：覆蓋面向〉, TK-EVD-008, TK-EVD-009, TK-SCP-006), tested through toolkit.coverage.coverage(inventory, cases,
exclusions).

Fast tests only. Expected values are worked by hand from the definition; the inventory is the real one of the
vulnerable sample, which has 5 unsupported scopes and 14 tables and policies.
"""
import unittest

from toolkit import coverage, inventory
from toolkit.tests.test_extract import sample_files


def case(case_id, result, valid=True, module='supabase-rls', covers=('public.documents',)):
    """One scheduled test: its result, whether its precondition and control held, the module whose judge it
    needs and the inventory items it exercises."""
    return {'id': case_id, 'result': result, 'valid': valid, 'module': module, 'covers': list(covers)}


INVENTORY = inventory.inventory(sample_files('vulnerable'))
RUN = [case('c1', 'passed'), case('c2', 'passed'), case('c3', 'failed'), case('c4', 'blocked')]


class TheNumbersOfARun(unittest.TestCase):
    def test_denominator_is_the_scheduled_cases_plus_the_unsupported_scopes(self):
        c = coverage.coverage(INVENTORY, RUN)
        self.assertEqual((c['denominator'], c['executed'], c['valid_judgements'], c['blocked'], c['errors'],
                          c['untested'], c['unsupported']), (9, 3, 3, 1, 0, 0, 5))
        self.assertAlmostEqual(c['effective_judgement_rate'], 3 / 9)


class BlockedErrorAndUntestedCasesStayInTheDenominator(unittest.TestCase):
    """TK-EVD-008: nothing is silently taken out; more blocked cases lower the effective judgement rate."""

    def test_one_more_blocked_case_lowers_the_rate(self):
        before = coverage.coverage(INVENTORY, RUN)
        after = coverage.coverage(INVENTORY, RUN + [case('c5', 'blocked')])
        self.assertEqual((after['denominator'], after['blocked'], after['valid_judgements']), (10, 2, 3))
        self.assertAlmostEqual(after['effective_judgement_rate'], 3 / 10)
        self.assertLess(after['effective_judgement_rate'], before['effective_judgement_rate'])

    def test_error_and_untested_cases_count_too(self):
        c = coverage.coverage(INVENTORY, [case('c1', 'passed'), case('c2', 'error'), case('c3', 'untested'),
                                          case('c4', 'cancelled')])
        self.assertEqual((c['denominator'], c['valid_judgements'], c['errors'], c['untested'], c['cancelled']),
                         (9, 1, 1, 1, 1))

    def test_cancelled_cases_are_counted_apart_from_untested_ones_and_stay_in_the_denominator(self):
        c = coverage.coverage(INVENTORY, [case('c1', 'cancelled'), case('c2', 'cancelled'), case('c3', 'untested')])
        self.assertEqual((c['denominator'], c['cancelled'], c['untested'], c['executed']), (8, 2, 1, 0))

    def test_cases_of_a_module_that_is_not_loaded_are_not_counted_as_cancelled(self):
        without = inventory.inventory(sample_files('vulnerable'), modules=())
        self.assertEqual(coverage.coverage(without, [case('c1', 'cancelled')])['cancelled'], 0)

    def test_an_executed_case_whose_precondition_or_control_failed_is_not_a_valid_judgement(self):
        c = coverage.coverage(INVENTORY, [case('c1', 'passed'), case('c2', 'passed', valid=False)])
        self.assertEqual((c['executed'], c['valid_judgements'], c['denominator']), (2, 1, 7))


class WithoutTheModuleNothingIsJudgedAndCoverageDoesNotRise(unittest.TestCase):
    """TK-SCP-006: no module, no valid judgement; the cases and the unsupported scopes stay in the denominator."""

    WITHOUT = inventory.inventory(sample_files('vulnerable'), modules=())

    def test_cases_that_need_the_missing_module_are_unsupported_not_valid(self):
        c = coverage.coverage(self.WITHOUT, RUN)
        self.assertEqual((c['valid_judgements'], c['executed'], c['blocked']), (0, 0, 0))
        self.assertEqual(c['unsupported'], 6 + 4)  # six unsupported scopes and the four cases that needed the module
        self.assertEqual(c['denominator'], 4 + 6)

    def test_the_rate_is_lower_and_the_denominator_is_not_smaller_than_with_the_module(self):
        with_module = coverage.coverage(INVENTORY, RUN)
        without = coverage.coverage(self.WITHOUT, RUN)
        self.assertGreaterEqual(without['denominator'], with_module['denominator'])
        self.assertLess(without['effective_judgement_rate'], with_module['effective_judgement_rate'])
        self.assertEqual(without['effective_judgement_rate'], 0)


def exclusion(ref='nextjs-routes', reason='the project has no Next.js application', confirmed_by='owner', version='v1'):
    return {'ref': ref, 'reason': reason, 'confirmed_by': confirmed_by, 'version': version}


class ExclusionsNeedAReasonAConfirmerAndAVersion(unittest.TestCase):
    """TK-EVD-009: an item that really does not apply can be excluded, with a reason, a confirmer and a version."""

    def test_a_complete_exclusion_takes_the_item_out_of_the_denominator(self):
        c = coverage.coverage(INVENTORY, RUN, [exclusion()])
        self.assertEqual((c['denominator'], c['unsupported']), (8, 4))
        self.assertEqual(c['excluded'], [exclusion()])
        self.assertEqual(c['rejected_exclusions'], [])

    def test_a_missing_field_means_the_item_is_not_excluded_and_says_which(self):
        for missing in ('reason', 'confirmed_by', 'version'):
            for blank in (None, '', '   '):
                with self.subTest(missing=missing, blank=blank):
                    incomplete = {**exclusion(), missing: blank}
                    c = coverage.coverage(INVENTORY, RUN, [incomplete])
                    self.assertEqual((c['denominator'], c['unsupported'], c['excluded']), (9, 5, []))
                    self.assertEqual(c['rejected_exclusions'], [{'ref': 'nextjs-routes', 'problem': f'missing {missing}'}])

    def test_an_exclusion_of_something_not_in_the_inventory_is_rejected(self):
        c = coverage.coverage(INVENTORY, RUN, [exclusion(ref='public.no_such_table')])
        self.assertEqual((c['denominator'], c['excluded']), (9, []))
        self.assertEqual(c['rejected_exclusions'], [{'ref': 'public.no_such_table', 'problem': 'not in the inventory'}])

    def test_excluding_an_inventoried_item_removes_the_cases_that_only_exercise_it(self):
        cases = RUN + [case('c5', 'passed', covers=['public.announcements']),
                       case('c6', 'passed', covers=['public.announcements', 'public.documents'])]
        c = coverage.coverage(INVENTORY, cases, [exclusion(ref='public.announcements')])
        self.assertEqual((c['denominator'], c['valid_judgements']), (4 + 1 + 5, 4))  # c5 is out, c6 stays


class ZeroDenominatorsAreNeverFullCoverage(unittest.TestCase):
    """TK-EVD-009: a zero denominator is 'not applicable' or 'insufficient data', never 100%."""

    NOTHING = {'loaded': ['supabase-rls'], 'facts': [], 'items': [], 'unresolved': [], 'completeness': 'complete'}

    def test_no_cases_and_nothing_inventoried_is_insufficient_data(self):
        c = coverage.coverage(self.NOTHING, [])
        self.assertEqual(c['denominator'], 0)
        self.assertIsNone(c['effective_judgement_rate'])
        self.assertEqual(c['states']['effective_judgement_rate'], 'insufficient_data')

    def test_everything_excluded_with_a_reason_is_not_applicable(self):
        only_routes = {**self.NOTHING, 'items': [{'scope': 'nextjs-routes', 'state': 'unsupported', 'reason': 'x'}]}
        c = coverage.coverage(only_routes, [], [exclusion()])
        self.assertEqual(c['denominator'], 0)
        self.assertIsNone(c['effective_judgement_rate'])
        self.assertEqual(c['states']['effective_judgement_rate'], 'not_applicable')

    def test_a_measured_rate_says_so(self):
        self.assertEqual(coverage.coverage(INVENTORY, RUN)['states']['effective_judgement_rate'], 'measured')


class TheTwoOtherRates(unittest.TestCase):
    """〈定義：覆蓋面向〉: tool support rate and required-test completion rate (formulas pending confirmation)."""

    def test_tool_support_rate_is_the_supported_share_of_the_denominator(self):
        c = coverage.coverage(INVENTORY, RUN)
        self.assertAlmostEqual(c['tool_support_rate'], (9 - 5) / 9)

    def test_required_test_completion_rate_is_the_cases_with_a_passed_or_failed_result(self):
        c = coverage.coverage(INVENTORY, RUN)
        self.assertAlmostEqual(c['required_test_completion_rate'], 3 / 4)  # 3 of the 4 scheduled cases ran to a verdict

    def test_without_the_module_both_are_zero_and_never_higher(self):
        c = coverage.coverage(inventory.inventory(sample_files('vulnerable'), modules=()), RUN)
        self.assertEqual((c['tool_support_rate'], c['required_test_completion_rate']), (0, 0))

    def test_no_cases_means_no_completion_rate_rather_than_a_full_one(self):
        c = coverage.coverage(INVENTORY, [])
        self.assertIsNone(c['required_test_completion_rate'])
        self.assertEqual(c['states']['required_test_completion_rate'], 'insufficient_data')
        self.assertEqual(c['states']['tool_support_rate'], 'measured')


class OnlyTheKnownScopeIsClaimedWhenTheInventoryIsNotComplete(unittest.TestCase):
    """TK-EVD-009: with an unknown inventory, only coverage of the known scope may be claimed."""

    def test_a_complete_inventory_claims_the_whole_scope(self):
        self.assertEqual(coverage.coverage(INVENTORY, RUN)['claim'], 'whole_scope')

    def test_an_inventory_with_unresolved_content_or_a_missing_module_claims_the_known_scope_only(self):
        undone = inventory.inventory({'supabase/migrations/001.sql': 'do $$ begin end $$;'})
        for inv in (undone, inventory.inventory(sample_files('vulnerable'), modules=())):
            with self.subTest(completeness=inv['completeness']):
                self.assertEqual(coverage.coverage(inv, RUN)['claim'], 'known_scope_only')


class TablesAndPolicies(unittest.TestCase):
    """The 資料表與政策 row of 〈定義：覆蓋面向〉, counted from the inventory and the valid cases."""

    def test_the_vulnerable_sample(self):
        cases = [case('c1', 'passed', covers=['public.documents', 'public.documents: tenant members update documents']),
                 case('c2', 'failed', valid=False, covers=['public.tenants'])]
        t = coverage.coverage(INVENTORY, cases)['tables_and_policies']
        self.assertEqual(t, {'inventoried': 14, 'rls_enabled': 5, 'without_policy': 0, 'unresolved': 0, 'judged': 2})

    def test_a_table_with_rls_and_no_policy_is_counted_apart_from_one_without_rls(self):
        inv = inventory.inventory({'supabase/migrations/001.sql':
                                   'create table public.a (id int);\nalter table public.a enable row level security;\n'
                                   'create table public.b (id int);\ncreate table public.c (id int);\n'
                                   'alter table public.c enable row level security;\n'
                                   'create policy p on public.c for select using (true);\n'})
        t = coverage.coverage(inv, [])['tables_and_policies']
        self.assertEqual((t['inventoried'], t['rls_enabled'], t['without_policy'], t['judged']), (4, 2, 1, 0))

    def counts_for(self, files):
        t = coverage.coverage(inventory.inventory(files), [])['tables_and_policies']
        return t['rls_enabled'], t['without_policy']

    def test_the_last_state_of_a_table_counts_when_it_is_enabled_and_then_disabled(self):
        self.assertEqual(self.counts_for({'supabase/migrations/001.sql':
                                          'create table public.a (id int);\n'
                                          'alter table public.a enable row level security;\n'
                                          'alter table public.a disable row level security;\n'}), (0, 0))

    def test_the_last_state_also_counts_when_it_is_disabled_and_then_enabled(self):
        self.assertEqual(self.counts_for({'supabase/migrations/001.sql':
                                          'create table public.a (id int);\n'
                                          'alter table public.a disable row level security;\n'
                                          'alter table public.a enable row level security;\n'}), (1, 1))

    def test_a_later_migration_file_decides_over_an_earlier_one(self):
        create_and_enable = ('create table public.a (id int);\nalter table public.a enable row level security;\n')
        disable = 'alter table public.a disable row level security;\n'
        self.assertEqual(self.counts_for({'supabase/migrations/001.sql': create_and_enable,
                                          'supabase/migrations/002.sql': disable}), (0, 0))
        self.assertEqual(self.counts_for({'supabase/migrations/001.sql': disable,
                                          'supabase/migrations/002.sql': create_and_enable}), (1, 1))

    def test_one_table_being_disabled_does_not_change_another(self):
        sql = ('create table public.a (id int);\ncreate table public.b (id int);\n'
               'alter table public.a enable row level security;\nalter table public.b enable row level security;\n'
               'alter table public.a disable row level security;\n')
        self.assertEqual(self.counts_for({'supabase/migrations/001.sql': sql}), (1, 1))

    def test_unresolved_content_is_counted(self):
        inv = inventory.inventory({'supabase/migrations/001.sql': 'do $$ begin end $$;\ndrop table public.x;\n'})
        self.assertEqual(coverage.coverage(inv, [])['tables_and_policies']['unresolved'], 2)


class OnlyCodeFactsReachTheCounts(unittest.TestCase):
    """TK-DAT-007: an inventory that carries something that is not a CodeFact is not counted, it is refused."""

    def test_a_proposed_fact_with_a_model_field_is_refused(self):
        proposed = {**INVENTORY, 'facts': INVENTORY['facts'] + [
            {'kind': 'table', 'name': 'public.made_up', 'source': {'file': 'x.sql', 'line': 1}, 'method': 'model:claude',
             'confidence': 0.9}]}
        with self.assertRaises(ValueError) as raised:
            coverage.coverage(proposed, RUN)
        self.assertIn("method 'model:claude' is not a registered extraction rule", str(raised.exception))
        self.assertIn("field 'confidence' is not part of an extracted table fact", str(raised.exception))

    def test_the_inventory_of_the_samples_is_accepted(self):
        self.assertEqual(coverage.coverage(INVENTORY, RUN)['denominator'], 9)


if __name__ == '__main__':
    unittest.main()
