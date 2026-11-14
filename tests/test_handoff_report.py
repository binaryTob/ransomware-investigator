from pathlib import Path
import json
import os
import subprocess
import sys
import unittest

from tools.handoff_report import render_handoff, with_chronology
from tests.common import ROOT, ProjectTest

# Explicitly invented identifiers; no saved operations are bundled with the code.
ACTIONS = tuple((format(i, '032x'), 'Synthetic action ' + str(i),
                 'partial' if i == 7 else 'completed') for i in range(1, 12))
OPTIONS = {'actions': ACTIONS, 'cutoff': '2000-01-13'}


class HandoffReportTests(unittest.TestCase):
    def operations(self):
        return [{'operation_id': i, 'status': status,
                 'started_at': '2000-01-12T10:01:02+00:00',
                 'finished_at': '2000-01-13T00:30:00+00:00'} for i, _, status in ACTIONS]

    def source(self):
        return '# Synthetic report\n\n## Data\n\n<!-- VERIFIED_CHRONOLOGY -->'

    def test_dates_are_preserved_not_moved_to_declared_period_start(self):
        rendered = with_chronology(self.source(), self.operations(), **OPTIONS)
        self.assertIn('12/01/2000 10:01:02', rendered)
        self.assertIn('13/01/2000 00:30:00', rendered)
        self.assertNotIn('07/01/2000 10:01:02', rendered)
        self.assertIn('partial', rendered)

    def test_missing_duplicate_naive_reversed_or_later_dates_fail(self):
        bad = self.operations(); bad.append(bad[0].copy())
        for operations in (self.operations()[:-1], bad):
            with self.assertRaises((KeyError, ValueError)):
                with_chronology(self.source(), operations, **OPTIONS)
        for field, stamp in (('started_at', '2000-01-12T10:01:02'),
                             ('finished_at', '2000-01-11T00:00:00+00:00'),
                             ('finished_at', '2000-01-14T00:00:00+00:00')):
            operations = self.operations(); operations[0][field] = stamp
            with self.assertRaises(ValueError):
                with_chronology(self.source(), operations, **OPTIONS)

    def test_failed_scope_cannot_be_promoted_to_success(self):
        operations = self.operations(); operations[6]['status'] = 'completed'
        with self.assertRaises(ValueError):
            with_chronology(self.source(), operations, **OPTIONS)

    def test_timezone_conversion_is_explicit_UTC(self):
        operations = self.operations(); operations[0]['started_at'] = '2000-01-12T07:01:02-03:00'
        result = with_chronology(self.source(), operations, **OPTIONS)
        self.assertIn('12/01/2000 10:01:02', result)

    def test_new_html_omits_connection_status_and_private_stop_directive(self):
        source = (Path(__file__).parent / 'fixtures/reports/handoff.md').read_text()
        rendered = render_handoff(source, self.operations(), **OPTIONS)
        self.assertNotIn('disconnected', rendered.casefold())
        self.assertNotIn('devices connected', rendered.casefold())
        self.assertNotIn('private stop directive', rendered.casefold())
        self.assertIn('12/01/2000 10:01:02', rendered)
        self.assertIn('All examples are fictional.', rendered)
        self.assertNotIn('<script', rendered)
        self.assertEqual(rendered.count('<h1 '), 1)

    def test_reproducible_output_and_text_escaping(self):
        source = self.source() + '\n\n<script>synthetic</script>'
        first = render_handoff(source, self.operations(), **OPTIONS)
        self.assertEqual(first, render_handoff(source, self.operations(), **OPTIONS))
        self.assertNotIn('<script>synthetic</script>', first)
        self.assertIn('&lt;script&gt;', first)


class HandoffBuilderTests(ProjectTest):
    def test_direct_help_needs_neither_installation_nor_operational_data(self):
        result = subprocess.run([sys.executable, str(ROOT / 'tools/build_handoff_report.py'), '--help'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--source', result.stdout)
        self.assertIn('--cutoff', result.stdout)

    def test_explicit_synthetic_inputs_build_new_outputs_without_clobber(self):
        provenance = self.work / 'synthetic-provenance.json'
        operations = HandoffReportTests().operations()
        provenance.write_text(json.dumps({'actions': ACTIONS, 'operation_dates': operations}))
        output = self.work / 'report'
        command = [sys.executable, str(ROOT / 'tools/build_handoff_report.py'),
                   '--source', str(Path(__file__).parent / 'fixtures/reports/handoff.md'),
                   '--provenance', str(provenance), '--cutoff', OPTIONS['cutoff'], '--output', str(output)]
        env = os.environ.copy(); env['PYTHONDONTWRITEBYTECODE'] = '1'
        first = subprocess.run(command, capture_output=True, text=True, timeout=10, env=env)
        self.assertEqual(first.returncode, 0, first.stderr)
        report = (output / 'REPORT.html').read_bytes()
        self.assertNotIn(b'<script', report)
        self.assertIn(b'12/01/2000 10:01:02', report)
        self.assertTrue(json.loads(first.stdout)['recorded_dates_preserved'])
        again = subprocess.run(command, capture_output=True, timeout=10, env=env)
        self.assertNotEqual(again.returncode, 0)
        self.assertEqual((output / 'REPORT.html').read_bytes(), report)
