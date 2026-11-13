"""Compare committed table deltas, retaining columns and foreign-key identity."""
import collections
import json
import re

SNAPSHOT_SQL = r"""
CREATE FUNCTION pg_temp.gofree_mctl3_snapshot() RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE t record; rows jsonb; result jsonb := '{}';
BEGIN
 FOR t IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='public' AND c.relkind IN ('r','p') AND NOT c.relispartition ORDER BY c.relname
 LOOP
   EXECUTE format('SELECT COALESCE(jsonb_agg(to_jsonb(t)), ''[]'') FROM public.%I t',t.relname) INTO rows;
   result := result || jsonb_build_object(t.relname,rows);
 END LOOP;
 RETURN result;
END $$;
SELECT pg_temp.gofree_mctl3_snapshot();
"""
FK_SQL = """SELECT COALESCE(json_agg(json_build_array(c.conrelid::regclass::text,a.attname,c.confrelid::regclass::text)),'[]')
 FROM pg_constraint c JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=c.conkey[1]
 WHERE c.contype='f' AND cardinality(c.conkey)=1"""

def snapshot(sql):
    return json.loads(sql(SNAPSHOT_SQL).splitlines()[-1])

def diff(before, after, foreign_keys):
    ids = {}
    for table, rows in after.items():
        old_ids = {r['id'] for r in before.get(table,[]) if 'id' in r}
        new_ids = sorted({r['id'] for r in rows if 'id' in r and r['id'] not in old_ids}, key=str)
        ids[table] = {v:f'{{{table}:{i+1}}}' for i,v in enumerate(new_ids)}
    fks = {(table, column): target for table,column,target in foreign_keys}
    def normalize(v, table='', key=''):
        if isinstance(v,dict):
            row={k:normalize(x,table,k) for k,x in v.items()}
            if table=='user_smime_certs' and v.get('label')=='seed' and v.get('cert_pem')=='seed-cert': row['id']='{SMIME_SEED:'+str(v['user_id'])+'}'
            return row
        if isinstance(v,list):
            return [normalize(x,table,key) for x in v]
        if key == 'imap_uid_validity':
            assert isinstance(v,int) and v>0, 'UIDVALIDITY must be a nonzero generated timestamp'
            return '{UIDVALIDITY}'
        if key == 'id' or (table,key) in fks:
            v = ids.get(table if key=='id' else fks[table,key],{}).get(v,v)
        if key == 'private_key_enc' and table=='user_smime_certs': return '{VERIFIED_ENCRYPTED_PRIVATE_KEY}'
        if isinstance(v,str):
            if key not in ('issued_at','expires_at') and re.fullmatch(r'\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(\.\d+)?([+-]\d\d:\d\d|Z)?',v): return '{TIME}'
            if key == 'password_hash': return '{VERIFIED_PASSWORD_HASH}'
        return v
    result = {}
    for table in sorted(before.keys() | after.keys()):
        old = collections.Counter(json.dumps(normalize(r,table),sort_keys=True) for r in before.get(table,[]))
        new = collections.Counter(json.dumps(normalize(r,table),sort_keys=True) for r in after.get(table,[]))
        added = [json.loads(v) for v in sorted((new-old).elements())]
        removed = [json.loads(v) for v in sorted((old-new).elements())]
        if added or removed: result[table] = dict(added=added,removed=removed)
    return result

def expected_normalization(v):
    # Generated IDs are opaque labels, never lexicographic sequence positions.
    # Canonicalize labels by row content on BOTH recorded and observed deltas,
    # then rewrite every FK reference through that same bijection.
    def legacy(v):
        if isinstance(v,dict):
            row={k:('{UIDVALIDITY}' if k=='imap_uid_validity' else '{CURRENT_DATE}' if k=='sending_quota_reset_at' else legacy(x)) for k,x in v.items()}
            if v.get('label')=='seed' and v.get('cert_pem')=='seed-cert': row['id']='{SMIME_SEED:'+str(v['user_id'])+'}'
            return row
        if isinstance(v,list): return [legacy(x) for x in v]
        return v
    v=legacy(v)
    tables=v.get('database_effects',{}).get('tables',{})
    mapping={}
    def stable(row):
        content={k:x for k,x in row.items() if k!='id'}
        return re.sub(r'\{([a-z_]+):[0-9]+\}',r'{\1:ID}',json.dumps(content,sort_keys=True))
    for table,delta in tables.items():
        rows=[r for r in delta['added'] if isinstance(r.get('id'),str) and re.fullmatch(r'\{'+re.escape(table)+r':[0-9]+\}',r['id'])]
        keys=[stable(r) for r in rows]
        assert len(keys)==len(set(keys)), 'ambiguous generated row identities in '+table
        for index,row in enumerate(sorted(rows,key=stable),1): mapping[row['id']]='{'+table+':'+str(index)+'}'
    def rewrite(v):
        if isinstance(v,dict):return {k:rewrite(x) for k,x in v.items()}
        if isinstance(v,list):return [rewrite(x) for x in v]
        return mapping.get(v,v) if isinstance(v,str) else v
    v=rewrite(v)
    for delta in v.get('database_effects',{}).get('tables',{}).values():
        for action in ('added','removed'):delta[action].sort(key=lambda row:json.dumps(row,sort_keys=True))
    return v
