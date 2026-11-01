"""The observer, tested through document_row_state(env, marker).

Fast tests only: they check how the observer reports a read it could not make. Reads
against a real stack are covered by the environment tests in test_e1 and test_scan.
"""
import os
import tempfile
import unittest
from pathlib import Path

from toolkit import e1, observer


def unreachable_env():
    """An environment whose observer role is set but whose stack is not running."""
    return e1.Environment(project_dir=Path('.'), project_id='maz-no-stack', recipe={}, cli='',
                          observer={'role': 'maz_observer', 'password': 'unused', 'host': 'localhost'})


class ObservationToolUnavailable(unittest.TestCase):
    """TK-IDN-009: an observation that cannot be made is a failed observation, never a pass."""

    def test_missing_container_tool_is_a_failed_observation(self):
        with tempfile.TemporaryDirectory() as empty:
            saved = os.environ['PATH']
            os.environ['PATH'] = empty  # no docker executable can be found
            try:
                with self.assertRaises(observer.ObservationFailed):
                    observer.document_row_state(unreachable_env(), 'MARK-A-ALICE-PRIVATE')
            finally:
                os.environ['PATH'] = saved


class UnreadableObservation(unittest.TestCase):
    """TK-IDN-009: output the observer cannot read is a failed observation, never a pass.

    A stand-in `docker` on PATH prints the output; this checks only how a failed read is
    reported, never a pass or fail judgement (CODING_STANDARDS.md rule 12)."""

    def observe_with_tool_output(self, script):
        with tempfile.TemporaryDirectory() as d:
            tool = Path(d) / 'docker'
            tool.write_text('#!/bin/sh\n' + script + '\n', encoding='utf-8')
            tool.chmod(0o755)
            saved = os.environ['PATH']
            os.environ['PATH'] = d
            try:
                return observer.document_row_state(unreachable_env(), 'MARK-A-ALICE-PRIVATE')
            finally:
                os.environ['PATH'] = saved

    def test_output_that_is_not_text_is_a_failed_observation(self):
        with self.assertRaises(observer.ObservationFailed):
            self.observe_with_tool_output(r"printf '\377\376\375'")

    def test_output_in_an_unexpected_shape_is_a_failed_observation(self):
        with self.assertRaises(observer.ObservationFailed):
            self.observe_with_tool_output("echo 'not-a-count'")
