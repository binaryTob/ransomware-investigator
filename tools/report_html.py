"""Small escaped Markdown subset for local, script-free forensic reports.

No evidence IO. Raw HTML is text, not markup; links are explicit local anchors.
The renderer intentionally uses native CSS flow rather than editable/JS layout:
the deliverable must be immutable, offline and usable with scripting disabled.
"""
from __future__ import annotations

import hashlib
import html
import re
import unicodedata


def render_document(markdown, *, title, prefix='report'):
    """Render caller-supplied text without embedding operational data or resources."""
    body, headings = markdown_blocks(markdown, prefix=prefix)
    navigation = ''.join(
        '<a href="#' + identifier + '">' + html.escape(label) + '</a>'
        for level, identifier, label in headings if level <= 2
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="robots" content="noindex,nofollow,noarchive">'
        '<meta name="referrer" content="no-referrer">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        'style-src \'unsafe-inline\'; img-src data:; base-uri \'none\'; '
        'form-action \'none\'; connect-src \'none\'">'
        '<title>' + html.escape(title) + '</title><style>' + CSS + '</style>'
        '</head><body><a class="skip" href="#content">Skip to report</a>'
        '<div class="shell"><aside class="rail"><p class="brand">Ransomware Investigator</p>'
        '<nav class="desktop-index" aria-label="Report contents">' + navigation + '</nav>'
        '<details class="mobile-index"><summary>Contents</summary><nav>' + navigation + '</nav></details>'
        '</aside><main class="document" id="content">' + body + '</main></div></body></html>'
    )


def render_report(base: bytes, update: str, *, expected_base_sha256: str) -> str:
    """Require an explicit source digest instead of a hardcoded investigation."""
    if (not re.fullmatch(r'[0-9a-f]{64}', expected_base_sha256)
            or hashlib.sha256(base).hexdigest() != expected_base_sha256):
        raise ValueError('Immutable source Markdown hash mismatch')
    base_body, _ = markdown_blocks(base.decode('utf-8'), prefix='base', heading_shift=1)
    update_body, _ = markdown_blocks(update, prefix='update', heading_shift=1)
    # These blocks have already been escaped. Only this fixed wrapper adds HTML.
    wrapper = render_document('# Local report', title='Local report')
    marker = '</main>'
    return wrapper.replace(marker, '<p>Source SHA-256: <code>' + expected_base_sha256
                           + '</code></p>' + update_body + base_body + marker, 1)


TOKEN = re.compile(r'(`[^`\n]+`|\*\*[^\n]+?\*\*|\[([^\]\n]+)\]\(([^)\n]+)\))')


def inline(text, link_map):
    result, cursor = [], 0
    for match in TOKEN.finditer(text):
        result.append(html.escape(text[cursor:match.start()]))
        token = match[0]
        if token.startswith('`'):
            result.append('<code>' + html.escape(token[1:-1]) + '</code>')
        elif token.startswith('**'):
            result.append('<strong>' + inline(token[2:-2], link_map) + '</strong>')
        else:
            label, target = match[2], link_map.get(match[3])
            if target is not None:
                if not re.fullmatch(r'#[a-z0-9-]+', target):
                    raise ValueError('Only explicit local report anchors are permitted')
                result.append('<a href="' + target + '">' + html.escape(label) + '</a>')
            else:
                result.append(html.escape(label + ' (' + match[3] + ')'))
        cursor = match.end()
    result.append(html.escape(text[cursor:]))
    return ''.join(result)


def slug(text):
    ascii_text = unicodedata.normalize('NFKD', text).encode('ascii', 'ignore').decode().lower()
    return re.sub(r'[^a-z0-9]+', '-', ascii_text).strip('-') or 'section'


def markdown_blocks(markdown, *, prefix, heading_shift=0, link_map=None):
    """Return escaped blocks and a heading index; reject ambiguous duplicate ids."""
    link_map = link_map or {}
    lines = markdown.splitlines()
    output, headings, ids = [], [], set()
    i, table_no = 0, 0
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            i += 1
            continue
        heading = re.fullmatch(r'(#{1,5}) (.+)', line)
        if heading:
            level = len(heading[1]) + heading_shift
            if level > 6:
                raise ValueError('Heading nesting exceeds HTML hierarchy')
            identifier = prefix + '-' + slug(heading[2])
            if identifier in ids:
                raise ValueError('Duplicate report heading')
            ids.add(identifier)
            headings.append((level, identifier, heading[2]))
            output.append(f'<h{level} id="{identifier}">{inline(heading[2], link_map)}</h{level}>')
            i += 1
        elif line.startswith('|'):
            rows = []
            while i < len(lines) and lines[i].strip().startswith('|'):
                rows.append([cell.strip() for cell in lines[i].strip().strip('|').split('|')])
                i += 1
            if len(rows) < 2 or not all(re.fullmatch(r':?-{3,}:?', c) for c in rows[1]):
                raise ValueError('Malformed Markdown table')
            if any(len(r) != len(rows[0]) for r in rows):
                raise ValueError('Unequal Markdown table columns')
            table_no += 1
            label = 'Tabla ' + str(table_no) + ' · ' + (headings[-1][2] if headings else 'Datos')
            output.append('<div class="table-scroll" tabindex="0" role="region" aria-label="' + html.escape(label, quote=True) + '"><table><caption class="sr-only">' + html.escape(label) + '</caption><thead><tr>')
            output.extend('<th scope="col">' + inline(c, link_map) + '</th>' for c in rows[0])
            output.append('</tr></thead><tbody>')
            for row in rows[2:]:
                output.append('<tr>' + ''.join('<td>' + inline(c, link_map) + '</td>' for c in row) + '</tr>')
            output.append('</tbody></table></div>')
        elif line.startswith('- '):
            output.append('<ul>')
            while i < len(lines) and lines[i].strip().startswith('- '):
                output.append('<li>' + inline(lines[i].strip()[2:], link_map) + '</li>')
                i += 1
            output.append('</ul>')
        else:
            paragraph = [line]
            i += 1
            while i < len(lines) and lines[i].strip() and not re.match(r'^(#{1,5} |\||- )', lines[i].strip()):
                paragraph.append(lines[i].strip())
                i += 1
            output.append('<p>' + inline(' '.join(paragraph), link_map) + '</p>')
    return '\n'.join(output), headings


CSS = '''
:root{color-scheme:light;--paper:#fff;--canvas:#eef2f3;--ink:#182e36;--muted:#4c626b;--line:#cbd7db;--accent:#09655d;--soft:#e9f4f1;--warn:#87420e;--warn-soft:#fff3e6;--space:8px}
*{box-sizing:border-box}html{scroll-padding-top:24px}body{margin:0;background:var(--canvas);color:var(--ink);font:400 16px/1.7 system-ui,-apple-system,"Segoe UI",sans-serif;overflow-wrap:anywhere}a{color:var(--accent);text-underline-offset:4px}a:hover{text-decoration-thickness:2px}:focus-visible{outline:3px solid var(--accent);outline-offset:4px}h1,h2,h3,h4{line-height:1.2;text-wrap:balance}p,li{text-wrap:pretty}p{margin:16px 0}h1{font-size:clamp(32px,4vw,56px);letter-spacing:-.04em;margin:24px 0}h2{font-size:28px;margin:56px 0 24px;border-top:1px solid var(--line);padding-top:32px;letter-spacing:-.025em}h3{font-size:24px;margin:40px 0 16px}h4{font-size:20px;margin:32px 0 16px}ul{padding-left:24px}li{padding-left:4px;margin:8px 0}strong{font-weight:650}code{font:400 .9em/1.6 ui-monospace,"Cascadia Code",monospace;overflow-wrap:anywhere;white-space:normal;background:var(--canvas);padding:2px 4px;border-radius:2px}table{width:100%;border-collapse:collapse;table-layout:fixed;font-size:16px;line-height:1.55}th,td{padding:16px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line);overflow-wrap:anywhere}th{background:var(--soft);font-weight:650}tbody tr:nth-child(even){background:var(--canvas)}.table-scroll{max-width:100%;overflow-x:auto;margin:24px 0 32px;border:1px solid var(--line)}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}.skip{position:fixed;top:8px;left:8px;transform:translateY(-200%);padding:12px 24px;background:var(--paper);z-index:10}.skip:focus{transform:none}.shell{max-width:1480px;margin:auto;display:grid;grid-template-columns:256px minmax(0,1fr);gap:32px;padding:32px}.rail{position:sticky;top:32px;align-self:start;max-height:calc(100dvh - 64px);overflow-y:auto;padding:8px}.brand{font-weight:750;font-size:20px;line-height:1.2;margin:0 0 8px}.rail small{display:block;color:var(--muted);font-size:16px;margin-bottom:24px}.rail a{display:block;padding:12px 8px;min-height:44px;text-decoration:none;border-bottom:1px solid var(--line);line-height:1.4}.rail a:hover{background:var(--soft)}.rail .nav-label{font-weight:650;margin:24px 8px 8px}.document{min-width:0;background:var(--paper);padding:48px 56px;border-top:8px solid var(--accent)}.document>header{border-bottom:1px solid var(--line);padding-bottom:32px}.topline{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;color:var(--muted)}.status{display:inline-block;padding:4px 12px;background:var(--soft);color:var(--accent);font-weight:650}.lede{font-size:20px;color:var(--muted);max-width:56ch}.decision{border-left:4px solid var(--warn);padding:16px 24px;background:var(--warn-soft);margin:32px 0}.decision h2{font-size:24px;padding:0;border:0;margin:0 0 8px}.decision p{margin:8px 0}.overview{display:grid;grid-template-columns:96px minmax(0,1fr);margin:24px 0}.overview dt{font-weight:750;border-top:1px solid var(--line);padding:16px 16px 16px 0}.overview dd{margin:0;padding:16px 0;border-top:1px solid var(--line)}.intro-note,.source-note{font-size:16px;color:var(--muted)}.base-banner{margin:56px 0 24px;padding:24px;border:1px solid var(--line);background:var(--soft)}.base-banner h2{margin:0 0 16px;border:0;padding:0}.base-banner p{margin:8px 0}section{min-width:0}footer{margin-top:56px;border-top:1px solid var(--line);padding-top:24px;color:var(--muted)}.back{display:inline-block;min-height:44px;padding:12px 0}
@media(min-width:1440px){.document{padding:56px 64px}}
@media(max-width:1024px){.shell{grid-template-columns:208px minmax(0,1fr);gap:16px;padding:16px}.document{padding:32px}.rail{top:16px;max-height:calc(100dvh - 32px)}}
@media(max-width:768px){.shell{display:block;padding:16px}.rail{position:static;max-height:none;padding:8px 0 24px}.rail nav{display:flex;gap:8px;flex-wrap:wrap}.rail nav a{padding:8px 12px;border:1px solid var(--line);background:var(--paper)}.rail .nav-label{display:none}.rail small{margin-bottom:16px}.document{padding:32px 24px}h2{font-size:24px}h3{font-size:20px}th,td{padding:12px}.topline{display:block}.status{margin-top:8px}}
@media(max-width:480px){.shell{padding:8px}.document{padding:24px 16px}h1{font-size:32px}h2{margin-top:40px}.overview{grid-template-columns:72px minmax(0,1fr)}.table-scroll table{min-width:560px}.table-scroll{margin-right:0}.decision{padding:16px}.rail nav a{font-size:16px}.base-banner{padding:16px}}
@media(prefers-color-scheme:dark){:root{color-scheme:dark;--paper:#17252b;--canvas:#101b20;--ink:#e3eded;--muted:#b6c9cd;--line:#40565d;--accent:#83d9c5;--soft:#203b3b;--warn:#ffcc98;--warn-soft:#3d2d20}}
@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;animation:none!important;transition:none!important}}
.mobile-index{display:none}
@media(max-width:768px){.desktop-index{display:none!important}.mobile-index{display:block}.mobile-index summary{min-height:44px;padding:8px 12px;background:var(--paper);border:1px solid var(--line);color:var(--accent);cursor:pointer}.mobile-index nav{padding-top:8px}.rail{padding-bottom:16px}.rail .brand br{display:none}.rail .brand br:after{content:" "}.rail small{margin-bottom:8px}}
@page{size:A4;margin:16mm}
@media print{:root{color-scheme:light;--paper:#fff;--canvas:#fff;--ink:#111;--muted:#333;--line:#bbb;--accent:#174d45;--soft:#f2f6f5;--warn:#653000;--warn-soft:#fff}body{font-size:10pt;line-height:1.5;background:white}.shell{display:block;max-width:none;padding:0}.rail,.skip,.back{display:none}.document{padding:0;border:0}h1{font-size:28pt}h2{font-size:18pt;margin-top:24pt;padding-top:12pt}h3{font-size:14pt}h4{font-size:12pt}h1,h2,h3,h4{break-after:avoid}p,li{orphans:3;widows:3}table{font-size:8pt;table-layout:fixed;min-width:0!important}th,td{padding:6pt}thead{display:table-header-group}tr{break-inside:avoid}.table-scroll{overflow:visible;border:0}.topline,.intro-note,.source-note,footer{font-size:9pt}.lede{font-size:13pt}.decision{break-inside:avoid}.base-banner{break-before:page}a{color:inherit;text-decoration:none}code{font-size:8pt}footer{margin-top:24pt}}
'''

