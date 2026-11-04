"""Layout of the test files themselves: what discover runs and what running a file directly runs agree."""
import ast
import tempfile
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent


def _is_main_guard(node):
    """`if __name__ == '__main__':` at the top level, either side of the ==."""
    t = node.test if isinstance(node, ast.If) else None
    if not (isinstance(t, ast.Compare) and len(t.ops) == 1 and isinstance(t.ops[0], ast.Eq)):
        return False
    sides = [t.left, t.comparators[0]]
    return (any(isinstance(n, ast.Name) and n.id == '__name__' for n in sides)
            and any(isinstance(n, ast.Constant) and n.value == '__main__' for n in sides))


def main_guard_problems(path):
    """Top-level statements after the file's `if __name__ == '__main__'` block, as 'file:line' problems."""
    body = ast.parse(Path(path).read_text(encoding='utf-8'), filename=str(path)).body
    guards = [i for i, node in enumerate(body) if _is_main_guard(node)]
    if not guards:
        return []
    return [f'{Path(path).name}:{node.lineno}: top-level code after the if __name__ == \'__main__\' block '
            f'is skipped when the file is run directly; move it above the block'
            for node in body[guards[0] + 1:]]


class MainGuardIsLast(unittest.TestCase):
    """A test class after `if __name__ == '__main__': unittest.main()` runs under discover but not when the
    file is run directly, so the guard must be the last top-level statement."""

    def problems_in(self, source):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'test_x.py'
            path.write_text(source, encoding='utf-8')
            return main_guard_problems(path)

    def test_code_after_the_guard_is_named_with_its_line(self):
        problems = self.problems_in("import unittest\n\nif __name__ == '__main__':\n    unittest.main()\n\n\n"
                                   "class Late(unittest.TestCase):\n    pass\n")
        self.assertEqual(len(problems), 1, problems)
        self.assertIn('test_x.py:7', problems[0])
        reversed_guard = self.problems_in("import unittest\n\nif '__main__' == __name__:\n    unittest.main()\n\n\n"
                                          "class Late(unittest.TestCase):\n    pass\n")
        self.assertEqual(len(reversed_guard), 1, reversed_guard)

    def test_a_guard_at_the_end_or_no_guard_is_fine(self):
        self.assertEqual(self.problems_in("import unittest\n\n\nclass A(unittest.TestCase):\n    pass\n\n\n"
                                          "if __name__ == '__main__':\n    unittest.main()\n"), [])
        self.assertEqual(self.problems_in("import unittest\n\n\nclass A(unittest.TestCase):\n    pass\n"), [])

    def test_every_test_file_has_its_guard_last(self):
        problems = [p for f in sorted(TESTS.glob('test_*.py')) for p in main_guard_problems(f)]
        self.assertEqual(problems, [])


if __name__ == '__main__':
    unittest.main()
