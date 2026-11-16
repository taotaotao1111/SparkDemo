"""Attach a retained investigation review only to its original captured evidence."""
import copy
import json
from pathlib import Path


def attach_resolution(case, resolution_path):
    """Retain user-confirmed metric scope without claiming a network fix or a tool query."""
    path = Path(resolution_path)
    if not path.is_file():
        return case
    packet = json.loads(path.read_text())
    data = case.get('data', {})
    incident = data.get('incident', {})
    binding = packet['binding']
    if (data.get('application', 'circles') != binding['application']
            or incident.get('traceId') not in binding['traceIds']
            or incident.get('error') != binding['error']):
        return case
    if not any(all(incident.get(k) == expected.get(k) for k in ['traceId', 'timestamp', 'bundle', 'endpoint', 'method'])
               for expected in binding.get('incidents', [])):
        return case
    packet = copy.deepcopy(packet)
    record = packet.pop('record')
    data['metricResolution'] = packet
    if not any(r['id'] == record['id'] for r in data.get('records', [])):
        data.setdefault('records', []).append(record)
    return case


def attach_review(case, review_path):
    """Preserve original acquisition times; an archived review is not a new query."""
    path = Path(review_path)
    if not path.is_file():
        return case
    review = json.loads(path.read_text())
    data = case.get('data', {})
    incident = data.get('incident', {})
    expected = review['binding']
    # A Trace alone can cover several attempts. Require the incident and source hash.
    if any(incident.get(key) != expected[key] for key in ['traceId', 'timestamp', 'bundle', 'endpoint', 'method']):
        return case
    anchors = [r for r in data.get('records', [])
               if r.get('type') == 'client-log'
               and r.get('traceId') == expected['traceId']
               and r.get('payload', {}).get('fileSha256') == expected['nativeFileSha256']
               and r.get('payload', {}).get('networkMetrics', {}).get('requestCallEndTimestamp') == expected['nativeEndTimestamp']]
    if not anchors:
        return case
    packet = copy.deepcopy(review)
    records = packet.pop('records')
    queries = packet.pop('queries')
    packet['sourceRecordIds'] = [r['id'] for r in anchors]
    data['evidenceReview'] = packet
    # Stable review IDs keep refreshes idempotent and leave original records intact.
    existing = {r['id'] for r in data.get('records', [])}
    data.setdefault('records', []).extend(r for r in records if r['id'] not in existing)
    query_ids = {q['id'] for q in data.get('queries', [])}
    data.setdefault('queries', []).extend(q for q in queries if q['id'] not in query_ids)
    data.setdefault('collection', {})['queryCount'] = len(data['queries'])
    return case
