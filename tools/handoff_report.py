"""Generic local handoff reports. All chronology and labels are explicit inputs."""
from __future__ import annotations

from datetime import date, datetime, timezone
import re

from tools.report_html import render_document


def with_chronology(source, operations, *, actions, cutoff):
    """Require exact expected operations/statuses; preserve original UTC dates."""
    marker = '<!-- VERIFIED_CHRONOLOGY -->'
    if source.count(marker) != 1:
        raise ValueError('One explicit chronology placeholder is required')
    cutoff_date = date.fromisoformat(cutoff)
    lookup = {}
    for operation in operations:
        identifier = operation['operation_id']
        if identifier in lookup:
            raise ValueError('Duplicate chronology operation')
        lookup[identifier] = operation
    if len({item[0] for item in actions}) != len(actions):
        raise ValueError('Duplicate expected action')
    if set(lookup) != {item[0] for item in actions}:
        raise ValueError('Chronology differs from the explicit expected operations')
    rows = ['| Action and ID | Started UTC | Finished UTC | Status |', '|---|---|---|---|']
    for identifier, label, status in actions:
        if (not isinstance(identifier, str) or not re.fullmatch(r'[0-9a-f]{32}', identifier)
                or any(not isinstance(v, str) or not v or any(c in v for c in '\n\r|')
                       for v in (label, status))):
            raise ValueError('Invalid bounded chronology fields')
        operation = lookup[identifier]
        if operation['status'] != status:
            raise ValueError('Chronology status differs from saved source')
        dates = []
        for field in ('started_at', 'finished_at'):
            stamp = datetime.fromisoformat(operation[field])
            if stamp.tzinfo is None:
                raise ValueError('Naive chronology timestamp is not permitted')
            dates.append(stamp.astimezone(timezone.utc))
        if dates[1] < dates[0]:
            raise ValueError('Chronology finish precedes start')
        if any(stamp.date() > cutoff_date for stamp in dates):
            raise ValueError('Operation is later than the report cutoff')
        shown = [stamp.strftime('%d/%m/%Y %H:%M:%S') for stamp in dates]
        rows.append(f'| {label} · `{identifier}` | {shown[0]} | {shown[1]} | {status} |')
    return source.replace(marker, '\n'.join(rows))


def render_handoff(source, operations, *, actions, cutoff):
    document = with_chronology(source, operations, actions=actions, cutoff=cutoff)
    return render_document(document, title='Local handoff report', prefix='handoff')
