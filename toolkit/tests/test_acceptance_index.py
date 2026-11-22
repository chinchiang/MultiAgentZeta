"""Keep the v0.1 evidence index traceable to the spec's acceptance paragraphs and named tests."""
import re
import unittest
from pathlib import Path


class AcceptanceIndex(unittest.TestCase):
    def test_required_rows_point_to_their_acceptance_condition_and_named_case(self):
        docs = Path(__file__).resolve().parents[2] / 'docs'
        spec = (docs / 'toolkit/spec.md').read_text().splitlines()
        required = {}
        for n, line in enumerate(spec, 1):
            if line.startswith('#### TK-'):
                requirement = line.split()[1]
                acceptance = None
            elif line.startswith('- **驗收**：'):
                acceptance = n
            elif line == '- **v0.1**：必做':
                self.assertIsNotNone(acceptance, requirement)
                required[requirement] = acceptance

        found = {}
        for row in (docs / 'v0.1-acceptance.md').read_text().splitlines():
            if not row.startswith('| [TK-'):
                continue
            requirement = row.split(']')[0][3:]
            with self.subTest(requirement=requirement):
                self.assertNotIn(requirement, found)
                target = re.search(r'\[驗收條件\]\(toolkit/spec.md\?plain=1#L(\d+)\)', row)
                self.assertIsNotNone(target)
                found[requirement] = int(target[1])
                case = re.search(r'\[(test_\w+)\]\(([^)]+)#L(\d+)\)', row)
                if case:
                    lines = (docs / case[2]).read_text().splitlines()
                    self.assertTrue(lines[int(case[3]) - 1].strip().startswith(f'def {case[1]}('))
                else:
                    self.assertIn('待補證據', row)
        self.assertEqual(found, required)
