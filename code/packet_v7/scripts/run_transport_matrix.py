"""Fixed causal diagnostic + corrected-topology stress; not final scientific data."""
from datetime import UTC,datetime
import json
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import home_lab_run as run
import portable_bundle as bundle
import run_closed_loop as pilot
from oran_trust_boundary.stable_linux_lab import StableLinuxLab as LinuxLab
from oran_trust_boundary.closed_loop_results import read_jsonl,score_server,check_offered_load,score_cohorts
from oran_trust_boundary.provenance import source_manifest


def fixed_jobs():
    jobs=[]
    # Balanced old/corrected ordering; 12 paired conditions, no retries.
    for replicate in range(6):
        for method in ('fixed_rule','evidence_feedback'):
            order=('dynamic_diagnostic_only','permanent') if replicate%2==0 else ('permanent','dynamic_diagnostic_only')
            for mode in order:
                jobs.append({'mode':mode,'method':method,'replicate':replicate})
    return jobs


def transport_summary(directory):
    rows=read_jsonl(directory/'server.jsonl',completed=True)
    summaries=[r for r in rows if r.get('type')=='server_summary']
    if len(summaries)!=1:raise RuntimeError('Missing server summary')
    observer=read_jsonl(directory/'server.jsonl.transport.jsonl',completed=True)
    if observer[-1].get('kind')!='observer_complete':raise RuntimeError('Incomplete transport observer')
    queues=[s for r in observer if r.get('kind')=='udp_queue' for s in r['sockets']]
    events=[r for r in observer if r.get('kind')=='neighbor' and r.get('dst')=='10.203.3.1']
    return {'echo_errors':sum(v['echo_errors'] for v in summaries[0]['sources'].values()),
            'server_summary':summaries[0], 'neighbor_events':events,
            'maximum_tx_queue_bytes':max((r['tx_queue_bytes'] for r in queues),default=0),
            'maximum_rx_queue_bytes':max((r['rx_queue_bytes'] for r in queues),default=0),
            'queue_sample_count':len(queues)}


def validate_dynamic_failure(directory,error):
    # Only the expected server-echo failure may be retained and followed by the
    # next predeclared diagnostic condition. Any other error stops this batch.
    if str(error)!='Server/client accounting mismatch or echo transport failure':raise error
    summary=transport_summary(directory)
    if summary['echo_errors']<=0 or summary['server_summary'].get('invalid')!=0:raise error
    clients={r:read_jsonl(directory/(r+'.jsonl'),completed=True) for r in ('legitimate','suspect')}
    settings=pilot.Settings()
    check_offered_load(clients['legitimate'],20,[{'start':0,'end':20,'pps':100}])
    check_offered_load(clients['suspect'],20,pilot.schedule(settings,'ineffective_action'))
    # Preserve raw server counters; check consistency without producing an
    # accepted score or changing a scorer. Failed echoes cannot arrive at clients.
    for role in clients:
        final=[r for r in clients[role] if r.get('type')=='cohort_summary']
        server=summary['server_summary']['sources'][role]
        if len(final)!=1 or not 0<=final[0]['received']<=server['echoed']<=server['received']<=final[0]['sent']:
            raise RuntimeError('Unexpected diagnostic accounting mismatch')
        if server['received']!=server['echoed']+server['echo_errors']:
            raise RuntimeError('Unaccounted diagnostic server packet')
        if server['received_bytes']!=512*server['received']:
            raise RuntimeError('Unaccounted diagnostic bytes')
    return summary


def stress(directory,case):
    directory.mkdir()
    # Deliberately extends beyond the planned <=600 pps, <=30 s final envelope.
    schedule=[{'start':0,'end':4,'pps':120},{'start':4,'end':50,'pps':case['pps']},
              {'start':50,'end':60,'pps':120}]
    with LinuxLab(directory,capacity_kbit=1000,packet_bytes=512) as lab:
        traffic=lab.start_traffic(duration_seconds=60,suspect_schedule=schedule,legitimate_pps=100,seed=case['seed'])
        completion=lab.finish()
        readback=lab.restore()
    clients={r:read_jsonl(directory/(r+'.jsonl'),completed=True) for r in ('legitimate','suspect')}
    quality={r:check_offered_load(clients[r],60,schedule if r=='suspect' else [{'start':0,'end':60,'pps':100}]) for r in clients}
    independent=score_server(read_jsonl(directory/'server.jsonl',completed=True),clients,60,512)
    before={r:score_cohorts(clients[r],1,3,512) for r in clients}
    after={r:score_cohorts(clients[r],53,59,512) for r in clients}
    if any(v['timely_delivery_ratio']<0.85 for phase in (before,after) for v in phase.values()):
        raise RuntimeError('Study-capacity baseline/restoration headroom failed')
    result={'case':case,'classification':'TRANSPORT_STRESS_NOT_FINAL','traffic_quality':quality,
            'server_whole_episode':independent,'headroom_before':before,'headroom_after':after,
            'final_readback':readback,'transport':transport_summary(directory)}
    run.write_json(directory/'stress_metrics.json',result)
    return result


def main():
    if sys.argv[1:]!=['--execute-approved-investigation']:
        raise RuntimeError('Explicit isolated investigation opt-in required')
    isolation=run.inspect_isolation();verified=bundle.verify_tree(ROOT);sources=source_manifest(ROOT)
    directory=ROOT/'results/local/transport_investigation_v6'
    run.checked_path(directory).mkdir() # Single-use fixed attempt, no overwrite.
    jobs=fixed_jobs()
    record={'status':'STARTED','classification':'CAUSAL_TRANSPORT_DIAGNOSTIC_NOT_FINAL',
            'created_utc':datetime.now(UTC).isoformat(),'jobs':jobs,'source_before':verified,
            'isolation_before':isolation,'paired':[],'stress':[],
            'stop_rule':'Fixed budget; no retry. Stop on any corrected-topology error or unknown safety/accounting error.'}
    run.write_json(directory/'PLAN.json',record)
    start=time.monotonic()
    try:
        settings=pilot.Settings.from_mapping(json.loads((ROOT/'configs/closed_loop_pilot.json').read_text()))
        for i,job in enumerate(jobs):
            if time.monotonic()-start>2100:raise RuntimeError('Investigation time budget exceeded')
            print(f'Transport diagnostic {i+1}/{len(jobs)}: {job}',flush=True)
            LinuxLab.neighbor_mode=job['mode']
            child=directory/f'paired_{i:03d}'
            result={'index':i,**job}
            try:
                pilot.episode(child,settings,'ineffective_action',job['method'],job['replicate'])
                result['status']='ORIGINAL_PACKET_CHECKS_PASSED'
            except ValueError as error:
                if job['mode']!='dynamic_diagnostic_only':raise
                validate_dynamic_failure(child,error)
                result.update(status='EXPECTED_DYNAMIC_TRANSPORT_FAILURE_RETAINED',error=str(error))
            result['transport']=transport_summary(child)
            result['isolation_after']=run.inspect_isolation()
            record['paired'].append(result)
            run.write_json(directory/f'receipt_{i:03d}.json',result)
            if source_manifest(ROOT)!=sources:raise RuntimeError('Source changed during diagnostic')
        LinuxLab.neighbor_mode='permanent'
        for i,pps in enumerate((400,600,600,400)):
            print(f'Transport stress {i+1}/4: {pps} pps for 46 s',flush=True)
            record['stress'].append(stress(directory/f'stress_{i:02d}',{'pps':pps,'seed':i}))
            run.inspect_isolation()
            if source_manifest(ROOT)!=sources:raise RuntimeError('Source changed during stress')
        record['status']='FIXED_INVESTIGATION_COMPLETE_CORRECTED_TRANSPORT_CHECKS_PASSED'
        record['causal_interpretation']='Review raw neighbor transitions and queue timing; absence of a dynamic failure is inconclusive about the historical cause.'
    except BaseException as error:
        record.update(status='INCOMPLETE_PRESERVE_ALL',error_type=type(error).__name__,error=str(error))
        raise
    finally:
        LinuxLab.neighbor_mode='permanent'
        try:
            record['source_after']=bundle.verify_tree(ROOT)
            record['isolation_after']=run.inspect_isolation()
        finally:
            record['elapsed_seconds']=time.monotonic()-start
            record['artifact_hashes']=run.file_hashes(directory)
            run.write_json(directory/'FINAL.json',record)
    print(record['status'],flush=True)


if __name__=='__main__':main()
