"""Where Chinese display names are defined (CODING_STANDARDS.md rule 10): `*_LABELS` only in report.py."""
import ast
import unittest
from pathlib import Path

TOOLKIT = Path(__file__).resolve().parents[1]


def label_definition_problems(source, filename):
    """Assignments to a name ending in `_LABELS` (or named `LABELS`) in source, as 'file:line: NAME …' problems."""
    problems = []
    for node in ast.walk(ast.parse(source, filename=filename)):
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            targets = [node.target]
        else:
            continue
        for name in (n for target in targets for n in _assigned_names(target)):
            if name == 'LABELS' or name.endswith('_LABELS'):
                problems.append((node.lineno, f'{filename}:{node.lineno}: {name} is defined outside report.py'))
    return [text for _, text in sorted(problems, key=lambda p: p[0])]


def _assigned_names(target):
    """The names an assignment target binds: Name, attribute and the parts of a tuple, list or star target."""
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Attribute):
        return [target.attr]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [n for part in target.elts for n in _assigned_names(part)]
    if isinstance(target, ast.Starred):
        return _assigned_names(target.value)
    return []


def scanned_files():
    """The files rule 10 applies to: toolkit/*.py except report.py (tests and tools/ are outside the scan)."""
    return [f for f in sorted(TOOLKIT.glob('*.py')) if f.name != 'report.py']


class DefinitionsAreFound(unittest.TestCase):
    def problems(self, source):
        return label_definition_problems(source, 'x.py')

    def test_a_module_level_definition_is_named_with_its_line(self):
        self.assertEqual(self.problems("import os\n\nFOO_LABELS = {'a': '甲'}\n"),
                         ["x.py:3: FOO_LABELS is defined outside report.py"])

    def test_definitions_inside_classes_and_functions_count(self):
        problems = self.problems("class A:\n    RUN_LABELS = {}\n\n\ndef f():\n    X_LABELS = {}\n    return X_LABELS\n")
        self.assertEqual([p.split(' ')[1] for p in problems], ['RUN_LABELS', 'X_LABELS'])
        self.assertTrue(problems[0].startswith('x.py:2:') and problems[1].startswith('x.py:6:'), problems)

    def test_annotated_augmented_and_unpacked_assignments_count(self):
        problems = self.problems("A_LABELS: dict = {}\nA_LABELS |= {}\nB_LABELS, other = {}, 1\n[C_LABELS] = [{}]\n")
        self.assertEqual([p.split(' ')[1] for p in problems], ['A_LABELS', 'A_LABELS', 'B_LABELS', 'C_LABELS'])

    def test_attribute_targets_count(self):
        self.assertEqual(len(self.problems("self.RUN_LABELS = {}\n")), 1)

    def test_a_name_that_is_just_labels_counts(self):
        self.assertEqual(self.problems("LABELS = {}\n"), ["x.py:1: LABELS is defined outside report.py"])

    def test_an_alias_of_a_report_table_counts(self):
        self.assertEqual(len(self.problems("import report\nREVIEW_LABELS = report.REVIEW_LABELS\n")), 1)

    def test_references_are_not_definitions(self):
        self.assertEqual(self.problems(
            "import report\n"
            "label = report.REVIEW_LABELS[x]\n"
            "for k in report.REVIEW_LABELS:\n    pass\n"
            "values = report.REVIEW_LABELS.values()\n"
            "report.REVIEW_LABELS['new'] = 'v'\n"
            "f(REVIEW_LABELS)\n"), [])

    def test_similar_names_are_not_definitions(self):
        self.assertEqual(self.problems("LABEL = 1\nlabels = 2\nFOO_LABELED = 3\nLABELS_FOR = 4\nMY_LABELSX = 5\n"), [])

    def test_a_file_without_assignments_has_no_problems(self):
        self.assertEqual(self.problems(""), [])
        self.assertEqual(self.problems("def f():\n    return 1\n"), [])


class RealFiles(unittest.TestCase):
    def test_the_scan_covers_the_toolkit_modules_but_not_report_tests_or_tools(self):
        names = {f.name for f in scanned_files()}
        self.assertTrue({'confirmation.py', 'item_rule.py', 'scan.py'} <= names, names)
        self.assertFalse(names & {'report.py', 'test_report.py'}, names)
        self.assertTrue((TOOLKIT / 'report.py').is_file() and (TOOLKIT / 'tests').is_dir() and (TOOLKIT / 'tools').is_dir())

    def test_report_py_really_defines_label_tables(self):
        """Guards against the scan going idle: if no file defined any, the check below would prove nothing."""
        problems = label_definition_problems((TOOLKIT / 'report.py').read_text(encoding='utf-8'), 'report.py')
        defined = {p.split(' ')[1] for p in problems}
        self.assertTrue({'REVIEW_LABELS', 'RUN_LABELS', 'FINDING_LABELS'} <= defined, defined)

    def test_no_other_toolkit_module_defines_a_labels_table(self):
        problems = [p for f in scanned_files()
                    for p in label_definition_problems(f.read_text(encoding='utf-8'), f.name)]
        self.assertEqual(problems, [])


if __name__ == '__main__':
    unittest.main()
