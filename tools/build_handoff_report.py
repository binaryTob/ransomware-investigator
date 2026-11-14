"""Build a local report from explicit project Markdown and chronology inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))

from ransomware_investigator.safety import ensure_user, project_path, read_project_file
from tools.handoff_report import render_handoff, with_chronology


def main():
    ensure_user()
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--provenance', type=Path, required=True)
    parser.add_argument('--cutoff', required=True, help='Explicit ISO calendar date')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = read_project_file(args.source).decode('utf-8')
    provenance = json.loads(read_project_file(args.provenance))
    options = {'actions': provenance['actions'], 'cutoff': args.cutoff}
    data = render_handoff(source, provenance['operation_dates'], **options).encode()
    text = with_chronology(source, provenance['operation_dates'], **options)
    output = project_path(args.output)
    output.mkdir(mode=0o700, exist_ok=False)
    digest = hashlib.sha256(data).hexdigest()
    for name, content in (('REPORT.html', data),
                          ('REPORT.html.sha256', (digest + '  REPORT.html\n').encode()),
                          ('report-source.md', text.encode())):
        with (output / name).open('xb') as stream:
            stream.write(content)
    print(json.dumps({'sha256': digest, 'bytes': len(data),
                      'recorded_dates_preserved': True, 'device_or_extracted_content_IO': False}))


if __name__ == '__main__':
    main()
