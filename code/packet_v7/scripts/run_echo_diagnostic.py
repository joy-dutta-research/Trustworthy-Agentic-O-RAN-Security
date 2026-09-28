"""Three fixed diagnostic episodes; does not complete or retry a scientific pilot."""
import argparse
from datetime import UTC,datetime
import json
from pathlib import Path
import sys
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import home_lab_run as run
import portable_bundle as bundle
import run_closed_loop as pilot
from oran_trust_boundary.provenance import source_manifest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-diagnostic',action='store_true')
    parser.add_argument('--qualification',type=Path,required=True)
    args=parser.parse_args()
    if not args.execute_diagnostic:parser.error('Explicit isolated diagnostic execution required')
    isolation=run.inspect_isolation()
    before=bundle.verify_tree(ROOT)
    sources=source_manifest(ROOT)
    run.validate_qualification(args.qualification,sources,run.environment_snapshot())
    root=ROOT/'results/local/echo_diagnostics'
    run.checked_path(root).mkdir(parents=True,exist_ok=True)
    lock=root/'.active-run.lock'
    # The wrapper guarantees a new release path, and this lock rejects overlap.
    with lock.open('x') as f:f.write('Diagnostic in progress; preserve on failure.')
    directory=root/(datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')+'-'+uuid.uuid4().hex[:8])
    directory.mkdir()
    record={'classification':'BOUNDED_TRANSPORT_DIAGNOSTIC_NOT_PILOT_OR_FINAL',
            'status':'STARTED','maximum_episodes':3,'maximum_attempts_per_episode':1,
            'fixed_condition':'ineffective_action/fixed_rule','replicates':[0,1,2],
            'traffic_duration_seconds':20,'isolation_before':isolation,
            'source_before':before,'source_files':sources,'episodes':[]}
    run.write_json(directory/'PLAN.json',record)
    try:
        settings=pilot.Settings.from_mapping(json.loads((ROOT/'configs/closed_loop_pilot.json').read_text()))
        for i in range(3):
            child=directory/f'episode_{i:04d}'
            item={'index':i,'condition':'ineffective_action','method':'fixed_rule','replicate':i}
            try:
                pilot.episode(child,settings,'ineffective_action','fixed_rule',i)
                item['status']='DIAGNOSTIC_EPISODE_PASSED_ORIGINAL_CHECKS'
            except ValueError as exc:
                # Preserve technical errors while collecting the predetermined
                # diagnostic budget. No scientific validity is assigned.
                item.update(status='TECHNICAL_ERROR_RETAINED',error_type=type(exc).__name__,error=str(exc))
            item['isolation_after']=run.inspect_isolation()
            record['episodes'].append(item)
            run.write_json(directory/f'diagnostic_receipt_{i:04d}.json',item)
            if source_manifest(ROOT)!=sources:raise RuntimeError('Source changed during diagnostic')
        record['status']='FIXED_DIAGNOSTIC_BUDGET_COMPLETED_NOT_SCIENTIFIC_RESULT'
    except BaseException as exc:
        record.update(status='DIAGNOSTIC_INTERRUPTED_PRESERVE_ALL',error_type=type(exc).__name__,error=str(exc))
        raise
    finally:
        try:
            record['source_after']=bundle.verify_tree(ROOT)
            record['isolation_after']=run.inspect_isolation()
        finally:
            record['artifact_hashes']=run.file_hashes(directory)
            run.write_json(directory/'FINAL.json',record)
            lock.unlink()
    print(json.dumps({'status':record['status'],'directory':str(directory)}))


if __name__=='__main__':main()
