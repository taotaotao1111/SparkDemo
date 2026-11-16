"""Company-shared investigation snapshots in platform PostgreSQL."""
import json
import copy
from scripts.vesta_evidence import redact
from pathlib import Path


def connect():
    import psycopg
    props={}
    for line in (Path(__file__).parent/'db.properties').read_text().splitlines():
        if line.strip() and not line.lstrip().startswith('#') and '=' in line:
            key,value=line.split('=',1);props[key.strip()]=value.strip()
    conn=psycopg.connect(host=props['db.host'],port=int(props['db.port']),user=props['db.username'],password=props['db.password'],dbname=props['db.database'],connect_timeout=5)
    conn.execute('CREATE TABLE IF NOT EXISTS trace_cases (id TEXT PRIMARY KEY, owner_email TEXT NOT NULL, trace_id TEXT NOT NULL, payload JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())')
    conn.execute('CREATE INDEX IF NOT EXISTS trace_cases_owner_time ON trace_cases(owner_email, updated_at DESC)')
    return conn


def save(actor,case):
    with connect() as conn:
        conn.execute('INSERT INTO trace_cases(id,owner_email,trace_id,payload) VALUES (%s,%s,%s,%s::jsonb) ON CONFLICT(id) DO UPDATE SET payload=EXCLUDED.payload,updated_at=NOW() WHERE trace_cases.owner_email=EXCLUDED.owner_email',(case['key'],actor,case['data']['incident']['traceId'],json.dumps(case,ensure_ascii=False)))


def shared_view(case):
    result=copy.deepcopy(case)
    collection=result['data'].setdefault('collection',{})
    collection['visibility']='company-shared'
    collection['semantics']='脱敏案件对公司登录用户共享；每次查询使用发起人的个人官方授权。'
    investigation=result['data'].get('investigation')
    if investigation and isinstance(investigation.get('question'),str):
        investigation['question']=redact(investigation['question'])
    return result


def list_cases(actor):
    with connect() as conn:
        rows=conn.execute('SELECT payload FROM (SELECT DISTINCT ON (trace_id) payload,updated_at FROM trace_cases ORDER BY trace_id,updated_at DESC) latest ORDER BY updated_at DESC LIMIT 40').fetchall()
        return [shared_view(row[0]) for row in rows]


def find(actor,trace):
    with connect() as conn:
        row=conn.execute('SELECT payload FROM trace_cases WHERE trace_id=%s ORDER BY updated_at DESC LIMIT 1',(trace,)).fetchone()
        return shared_view(row[0]) if row else None


def agent_connection():
    conn=connect()
    conn.execute('CREATE TABLE IF NOT EXISTS trace_agent_threads (id TEXT PRIMARY KEY, owner_email TEXT NOT NULL, payload JSONB NOT NULL, private_refs JSONB NOT NULL DEFAULT \'{}\'::jsonb, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())')
    return conn


def save_thread(actor,thread,refs):
    with agent_connection() as conn:
        conn.execute('INSERT INTO trace_agent_threads(id,owner_email,payload,private_refs) VALUES (%s,%s,%s::jsonb,%s::jsonb) ON CONFLICT(id) DO UPDATE SET payload=EXCLUDED.payload,private_refs=EXCLUDED.private_refs,updated_at=NOW() WHERE trace_agent_threads.owner_email=EXCLUDED.owner_email', (thread['id'],actor,json.dumps(thread,ensure_ascii=False),json.dumps(refs,ensure_ascii=False)))


def get_thread(actor,thread_id):
    with agent_connection() as conn:
        row=conn.execute('SELECT owner_email,payload,private_refs FROM trace_agent_threads WHERE id=%s',(thread_id,)).fetchone()
        if not row:return None
        # Sanitized reports are shared. Raw lookup references never cross owners.
        return {'thread':row[1],'refs':row[2] if row[0]==actor else {},'canContinue':row[0]==actor}


def list_threads(actor):
    with agent_connection() as conn:
        rows=conn.execute("SELECT payload->>'id',payload->>'title',payload->>'updatedAt',owner_email=%s, jsonb_array_length(payload->'rounds') FROM trace_agent_threads ORDER BY updated_at DESC LIMIT 40",(actor,)).fetchall()
        return [{'id':r[0],'title':r[1],'updatedAt':r[2],'canContinue':r[3],'roundCount':r[4]} for r in rows]
