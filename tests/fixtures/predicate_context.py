"""Disposable native A/B qualification; synthetic vectors only, no external services.

Run inside the explicit fixture image with a read-only root, no network, and
writable tmpfs at /tmp and /usr/lib/postgresql/17/lib. Mount the sealed runner at
/opt/torch-reviews and this script at /checks. Both libraries run against the same
physical HNSW index, restarting PostgreSQL between versions.
"""

import hashlib
import importlib.util
import json
import math
import os
import shutil
import subprocess
from pathlib import Path
from statistics import mean

import numpy as np
import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo


def run(*args):
    subprocess.run([str(x) for x in args], check=True)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    os.umask(0o077)
    spec = importlib.util.spec_from_file_location("frozen_reviews", "/opt/torch-reviews/runner.py")
    frozen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(frozen)
    spec2 = importlib.util.spec_from_file_location("candidate_pgvector", "/candidate/fannagent_pgvector/__init__.py", submodule_search_locations=["/candidate/fannagent_pgvector"])
    package_module = importlib.util.module_from_spec(spec2)
    import sys
    sys.modules["candidate_pgvector"] = package_module
    spec2.loader.exec_module(package_module)
    from candidate_pgvector.predicate_context import PredicateContextBackend, CONTEXT_FUNCTIONS
    from candidate_pgvector.native.features import CONTEXT_REGISTRY_HASH
    from candidate_pgvector.profiles import PREDICATE_CONTEXT_PROFILE
    from candidate_pgvector.prepared import PreparedPolicyCache

    class ContextBackend(frozen.TorchBackend):
        runtime_profile = PREDICATE_CONTEXT_PROFILE
        _execute_probe = PredicateContextBackend._execute_probe
        _bind_query_context = PredicateContextBackend._bind_query_context
        validate_policy = PredicateContextBackend.validate_policy

        def __init__(self, bundle, work):
            super().__init__(bundle, work)
            self._policies = PreparedPolicyCache(self.runtime_profile)

    libdir = Path("/usr/lib/postgresql/17/lib")
    # The tmpfs root belongs to root; copy its children without changing its mode.
    for source in Path("/opt/queue-fixture/baseline-lib").iterdir():
        target = libdir / source.name
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            shutil.copy2(source, target)
    lib = libdir / "vector.so"
    original_lib = Path("/opt/queue-fixture/candidate-vector.so")
    candidate_lib = Path("/opt/predicate-fixture/candidate-vector.so")
    assert digest(original_lib) != digest(candidate_lib)
    work = Path("/tmp/queue-statistics-fixture")
    work.mkdir(mode=0o700)
    (work / "socket").mkdir(mode=0o700)
    (work / ".torch-owned").write_text("synthetic-only\n")
    frozen.initialize_auth(work)
    run(
        "initdb",
        "-D",
        work / "pgdata",
        "--username=torch_owner",
        "--pwfile=" + str(work / "admin.pw"),
        "--auth-local=scram-sha-256",
        "--auth-host=reject",
        "--encoding=UTF8",
        "--locale=C",
    )
    calls = 0
    running = False

    def start():
        nonlocal running
        run(
            "pg_ctl",
            "-D",
            work / "pgdata",
            "-l",
            work / "server.log",
            "-w",
            "-t",
            "60",
            "-o",
            "-c listen_addresses='' -c unix_socket_directories="
            + str(work / "socket")
            + " -c unix_socket_permissions=0700 -c hba_file="
            + str(work / "pg_hba.conf")
            + " -c shared_buffers=128MB -c max_connections=8 -c log_statement=none",
            "start",
        )
        running = True

    def stop():
        nonlocal running
        if running:
            run("pg_ctl", "-D", work / "pgdata", "-m", "fast", "-w", "stop")
            running = False

    rng = np.random.default_rng(20261019)
    vectors = rng.normal(size=(4004, 16)).astype(np.float32)
    vectors /= np.linalg.norm(vectors, axis=1, keepdims=True)
    queries = [
        {
            "id": "synthetic-" + str(i),
            "k": 10,
            "vector": v.tolist(),
            "filter": {"field": "m_000000", "op": "gte", "value": 32},
        }
        for i, v in enumerate(vectors[4000:])
    ]
    fingerprints, references, benchmark = {}, {}, []
    backend = None
    try:
        start()
        with psycopg.connect(frozen.job_connection(work, admin=True), autocommit=True) as conn:
            conn.execute("CREATE DATABASE torch_reviews")
        admin_dsn = make_conninfo(frozen.job_connection(work, admin=True), dbname="torch_reviews")
        with psycopg.connect(admin_dsn, autocommit=True) as conn:
            password = (work / "reader.pgpass").read_text().strip().rsplit(":", 1)[1]
            conn.execute(
                sql.SQL("CREATE ROLE torch_reader LOGIN PASSWORD {}").format(sql.Literal(password))
            )
            conn.execute("CREATE EXTENSION vector")
            conn.execute(
                "CREATE TABLE reviews(id bigint PRIMARY KEY,"
                "embedding vector(16),total_votes bigint)"
            )
            with conn.cursor().copy("COPY reviews FROM STDIN") as copy:
                for i, vector in enumerate(vectors[:4000]):
                    text = "[" + ",".join(format(float(v), ".9g") for v in vector) + "]"
                    copy.write_row((i, text, i % 200))
            conn.execute("SET max_parallel_maintenance_workers=0")
            conn.execute(
                "CREATE INDEX reviews_hnsw ON reviews USING hnsw(embedding vector_cosine_ops) "
                "WITH(m=16,ef_construction=64)"
            )
            conn.execute("ANALYZE reviews")
            conn.execute(frozen.FUNCTIONS)
            conn.execute(CONTEXT_FUNCTIONS)
            conn.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
            conn.execute("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA fannagent FROM PUBLIC")
            conn.execute("GRANT CONNECT ON DATABASE torch_reviews TO torch_reader")
            conn.execute("GRANT USAGE ON SCHEMA public,fannagent TO torch_reader")
            conn.execute("GRANT SELECT ON reviews TO torch_reader")
            conn.execute("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA fannagent TO torch_reader")
            conn.execute("ALTER ROLE torch_reader SET default_transaction_read_only=on")
            conn.execute("CHECKPOINT")
            location, oid = conn.execute(
                "SELECT pg_relation_filepath('reviews_hnsw'),'reviews_hnsw'::regclass::oid"
            ).fetchone()
        index_path = work / "pgdata" / location
        index_hash = digest(index_path)
        (work / "database-identity.json").write_text(
            json.dumps(
                {
                    "index_oid": oid,
                    "index_identity": index_hash,
                }
            )
        )
        stop()

        bundle = Path('/opt/torch-reviews')
        def raw_policy(name, root='continue', context=False):
            return {'name':name, 'feature_groups':['basic','work','queue','distances'] + (['query_context'] if context else []), 'root':root}
        def branch(value, yes=True):
            return {'if':{'op':'eq','args':[{'feature':'query_predicate_threshold'},{'int':value if yes else value+1}]},'then':'stop','else':'continue'}
        cases=[]
        for i, v in enumerate(vectors[4000:]):
            for threshold in (None,0,32,108,2**63-1):
                cases.append({'id':'unrelated-'+str(i)+'-'+str(threshold),'k':10,'vector':v.tolist(),
                    'filter':None if threshold is None else {'field':'m_000000','op':'gte','value':threshold}})
        records={}; timings=[]; comparisons=0; branches=0
        for version,library in [('baseline',original_lib),('candidate',candidate_lib)]:
            shutil.copyfile(library,lib);start()
            backend=frozen.TorchBackend(bundle,work)
            backend.state['source_manifest']['settings']['hnsw.ef_search']='640'
            for q in cases:
                native=backend.execute_probe(q)
                legacy=backend.execute_probe(q,mode='policy',policy=backend.validate_policy(raw_policy('legacy')),trace=True)
                assert (legacy.ids,legacy.distances)==(native.ids,native.distances)
                checkpoints=legacy.evidence['checkpoints']
                fp={'ids':legacy.ids,'distances':legacy.distances,'checkpoints':checkpoints,
                    'work':{k:v for k,v in legacy.metadata['work_counters'].items() if not k.endswith('_ns')}}
                if version=='baseline':records[q['id']]=fp
                else:assert fp==records[q['id']];comparisons+=1
            backend.close();backend=None
            if version=='candidate':
                context=ContextBackend(bundle,work);context.state['source_manifest']['settings']['hnsw.ef_search']='640'
                backend=context
                for q in cases:
                    threshold=0 if q['filter'] is None else q['filter']['value']
                    reference=context.execute_probe(q,mode='policy',policy=context.validate_policy(raw_policy('context-continue',context=True)),trace=True)
                    old=records[q['id']]
                    assert (reference.ids,reference.distances)==(old['ids'],old['distances'])
                    assert reference.evidence['normalized']['feature_registry_hash']==CONTEXT_REGISTRY_HASH
                    prefix=[]
                    for c in reference.evidence['checkpoints']:
                        assert c['features']['query_predicate_threshold']==threshold
                        prefix.append({**c,'features':{n:v for n,v in c['features'].items() if n!='query_predicate_threshold'}})
                    assert prefix==old['checkpoints'];comparisons+=1
                    for yes in (True,False):
                        # max int64 false case uses max-1 instead of overflowing.
                        condition=branch(threshold,yes) if threshold<2**63-1 or yes else branch(threshold-1,True)
                        policy=context.validate_policy(raw_policy('getter-'+str(threshold)+'-'+str(yes),condition,True))
                        result=context.execute_probe(q,mode='policy',policy=policy,trace=True)
                        assert not result.metadata.get('policy_runtime_error') and not result.metadata.get('policy_fallback')
                        assert (result.metadata['stop_reason']=='policy_stop')==yes
                        if yes:
                            assert len(result.evidence['checkpoints'])==1
                            assert result.evidence['checkpoints'][0]==reference.evidence['checkpoints'][0]
                        else:assert (result.ids,result.distances)==(old['ids'],old['distances'])
                        branches+=1
                # Alternate filtered, unfiltered, and legacy requests on the same
                # session; every begin resets the request constant.
                q=cases[2];conn=context._connect()
                policy=context.validate_policy(raw_policy('context-reset',{'if':{'op':'is_available','args':[{'feature':'query_predicate_threshold'}]},'then':branch(32),'else':'continue'},True))
                context.install_policy(policy)
                from candidate_pgvector.native.transport import feature_set_hash
                legacy_groups=['basic','work','queue','distances']
                nonce='reset_test'
                params=('policy_agent',policy.policy_hash,None,nonce,10,1,'checkpoints',64*1024**2,
                    frozen.FEATURE_REGISTRY_HASH,feature_set_hash(legacy_groups),','.join(legacy_groups),False)
                with conn.transaction():
                    conn.execute('SELECT fannagent.begin_execution('+','.join(['%s']*12)+')',params)
                    statement,bindings=context._statement(q);rows=conn.execute(statement,bindings).fetchall()
                    meta=json.loads(conn.execute('SELECT fannagent.complete(%s,%s)',(nonce,len(rows))).fetchone()[0])
                assert meta['stop_reason']!='policy_stop' and not meta.get('policy_runtime_error')
                for groups,threshold,leaf in [('basic',32,1),('query_context',-1,1),('query_context',32,0),('query_context',32,2),('query_context',None,1)]:
                    bad=list(params);bad[0]='policy_noop';bad[1]=None;bad[5]=leaf;bad[10]=groups
                    try:
                        with conn.transaction():conn.execute('SELECT fannagent.begin_execution('+','.join(['%s']*12)+',%s::bigint)',(*bad,threshold))
                    except psycopg.Error:pass
                    else:raise AssertionError('Invalid native context accepted')
                # A failed begin and transaction rollback must not retain context.
                healthy=context.execute_probe(cases[0],mode='policy',policy=context.validate_policy(raw_policy('after-error',context=True)),trace=True)
                assert all(c['features']['query_predicate_threshold']==0 for c in healthy.evidence['checkpoints'])
                context.close();backend=None
                # Repeated paired timings include validation and binding in the
                # adapter clock; trace retrieval stays outside it as before.
                legacy=frozen.TorchBackend(bundle,work);legacy.state['source_manifest']['settings']['hnsw.ef_search']='640'
                context=ContextBackend(bundle,work);context.state['source_manifest']['settings']['hnsw.ef_search']='640'
                import random,time
                order=random.Random(20261019)
                for repeat in range(12):
                    for q in cases[:15]:
                        pair={};arms=[('legacy',legacy),('context',context)];order.shuffle(arms)
                        for name,b in arms:
                            before=__import__('time').perf_counter_ns()
                            result=b.execute_probe(q,mode='policy',policy=b.validate_policy(raw_policy('timing-'+name,context=name=='context')))
                            pair[name]={'reported_ms':result.latency_ms,'outer_ms':(__import__('time').perf_counter_ns()-before)/1e6}
                        timings.append(pair)
                legacy.close();context.close()
            verify=digest(index_path);assert verify==index_hash
            stop()
        report={'status':'passed','architecture':os.uname().machine,'synthetic_rows':4000,'dimensions':16,
            'cases':len(cases),'equivalence_comparisons':comparisons,'true_false_branches':branches,
            'baseline_library_sha256':digest(original_lib),'candidate_library_sha256':digest(candidate_lib),
            'runtime_profile_hash':PREDICATE_CONTEXT_PROFILE.fingerprint,'registry_hash':CONTEXT_REGISTRY_HASH,
            'timing_pairs':len(timings),'mean_reported_delta_ms':mean(p['context']['reported_ms']-p['legacy']['reported_ms'] for p in timings),
            'mean_outer_delta_ms':mean(p['context']['outer_ms']-p['legacy']['outer_ms'] for p in timings),
            'checks':['legacy cross-binary IDs distances work and trajectory','context trajectory and results unchanged',
                'native true/false getter branches','int64 bounds','unfiltered and zero distinction',
                'same-session disabled getter unavailable','rollback reset','invalid binding rejection','same physical index'],
            'Reviews_queries':0,'provider_calls':0,'scope':'local synthetic ARM only; Torch performance and deployment unqualified'}
        Path('/results/results.json').write_text(json.dumps(report,indent=2)+'\n')
        Path('/results/timings.json').write_text(json.dumps(timings)+'\n')
        print(json.dumps(report),flush=True)
    finally:
        if backend is not None:backend.close()
        stop()


if __name__=='__main__':main()
