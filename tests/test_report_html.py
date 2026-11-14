import hashlib
import unittest
from html.parser import HTMLParser
from pathlib import Path

from tools.report_html import inline, markdown_blocks, render_report

FIXTURES = Path(__file__).parent / 'fixtures/reports'


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids, self.links, self.tags, self.text = [], [], [], []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append(tag)
        if 'id' in attrs:
            self.ids.append(attrs['id'])
        if tag == 'a':
            self.links.append(attrs.get('href', ''))
        if tag == 'th':
            assert attrs.get('scope') == 'col'

    def handle_data(self, data):
        self.text.append(data)


class ReportHtmlTests(unittest.TestCase):
    def render(self, base, update):
        return render_report(base, update, expected_base_sha256=hashlib.sha256(base).hexdigest())

    def test_untrusted_raw_markup_and_code_are_escaped(self):
        rendered = inline('<script>alert(1)</script> `<img src=x onerror=evil()>`', {})
        self.assertNotIn('<script>', rendered)
        self.assertNotIn('<img', rendered)
        self.assertIn('&lt;script&gt;', rendered)
        self.assertIn('<code>&lt;img', rendered)

    def test_links_are_only_explicit_local_anchors(self):
        rendered = inline('[hostile](javascript:evil) [ok](local.md)', {'local.md': '#local'})
        self.assertNotIn('href="javascript:', rendered)
        self.assertIn('href="#local"', rendered)
        with self.assertRaises(ValueError):
            inline('[bad](local.md)', {'local.md': 'https://remote.invalid'})

    def test_markup_text_in_bold_is_still_escaped(self):
        self.assertEqual(inline('**<b>synthetic</b>**', {}), '<strong>&lt;b&gt;synthetic&lt;/b&gt;</strong>')

    def test_tables_and_lists_preserve_synthetic_values(self):
        result, headings = markdown_blocks('# Fixture\n\n| A | B |\n|---|---|\n| <x> | `123` |\n\n- alpha\n- beta', prefix='test', heading_shift=1)
        self.assertEqual(headings, [(2, 'test-fixture', 'Fixture')])
        self.assertIn('scope="col"', result)
        self.assertIn('&lt;x&gt;', result)
        self.assertIn('<li>beta</li>', result)

    def test_duplicate_ids_and_malformed_tables_rejected(self):
        for text in ('# Same\n\n# Same', '| A | B |\n|---|---|\n| only |'):
            with self.assertRaises(ValueError):
                markdown_blocks(text, prefix='test')

    def test_immutable_source_hash_is_enforced(self):
        for expected in ('0' * 64, 'not-a-hash'):
            with self.assertRaises(ValueError):
                render_report(b'synthetic modified report', '# Update', expected_base_sha256=expected)

    def test_local_redacted_document_integrity_and_no_active_content(self):
        base = (FIXTURES / 'base.md').read_bytes()
        update = (FIXTURES / 'update.md').read_text()
        rendered = self.render(base, update)
        page = Page(); page.feed(rendered)
        self.assertEqual(len(page.ids), len(set(page.ids)))
        for link in page.links:
            self.assertTrue(link.startswith('#'))
            self.assertIn(link[1:], page.ids)
        self.assertFalse(set(page.tags) & {'script', 'iframe', 'object', 'embed', 'form'})
        self.assertIn("connect-src 'none'", rendered)
        self.assertIn(hashlib.sha256(base).hexdigest(), rendered)
        self.assertIn('@media print', rendered)
        self.assertIn('prefers-reduced-motion', rendered)
        self.assertNotIn('contenteditable', rendered)
        text = ''.join(page.text)
        self.assertIn('<namespace>/extracted/', text)
        self.assertIn('120', text)
        self.assertIn('SAMPLE-001 through SAMPLE-004', text)
        for line in base.decode().splitlines():
            line = line.strip()
            if not line or line.startswith('#') or (line.startswith('|') and set(line) <= set('|-: ')):
                continue
            cells = line.strip('|').split('|') if line.startswith('|') else [line.removeprefix('- ')]
            for cell in cells:
                self.assertIn(cell.strip().replace('**', '').replace('`', ''), text)

    def test_render_is_reproducible(self):
        base = (FIXTURES / 'base.md').read_bytes()
        update = (FIXTURES / 'update.md').read_text()
        self.assertEqual(self.render(base, update), self.render(base, update))
