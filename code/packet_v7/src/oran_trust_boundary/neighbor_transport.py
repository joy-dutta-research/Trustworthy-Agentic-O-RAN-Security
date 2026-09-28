"""Scoped permanent neighbors for the fixed, uniquely owned packet topology.

No host changes, buffer tuning, retries, traffic or acceptance changes. Dynamic
mode exists only for a predeclared causal diagnostic, never the corrected pilot.
"""
import json
import re

EDGES = (
    ('legitimate','client0','router','legit0','10.203.1.1'),
    ('router','legit0','legitimate','client0','10.203.1.2'),
    ('suspect','client0','router','suspect0','10.203.2.1'),
    ('router','suspect0','suspect','client0','10.203.2.2'),
    ('server','server0','router','server0','10.203.3.1'),
    ('router','server0','server','server0','10.203.3.2'),
)


def require_owned(lab):
    lab._require_active()
    if not re.fullmatch(r'orcl-[0-9a-f]{12}', lab.prefix):
        raise RuntimeError('Invalid owned topology prefix')
    expected = {r: lab.prefix+'-'+r for r in ('legitimate','suspect','router','server')}
    if lab.namespaces != expected or set(lab._owned) != set(expected.values()) or len(lab._owned) != 4:
        raise RuntimeError('Only all four uniquely owned namespaces are permitted')


def planned_entries(lab):
    require_owned(lab)
    topology = lab.verify_isolation()
    result = []
    for role,device,peer,peer_device,address in EDGES:
        links = [x for x in topology[peer]['links'] if x.get('ifname') == peer_device]
        mac = links[0].get('address','') if len(links) == 1 else ''
        if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',mac) or int(mac[:2],16)&1 or mac == '00:00:00:00:00:00':
            raise RuntimeError('Invalid point-to-point peer MAC readback')
        result.append({'role':role,'device':device,'dst':address,'lladdr':mac})
    return result


def verify_entries(lab, entries):
    require_owned(lab)
    readback = {}
    for role in lab.namespaces:
        rows = json.loads(lab._ip(role,'-4','-j','neigh','show').stdout)
        expected = [r for r in entries if r['role'] == role]
        if not isinstance(rows,list) or len(rows) != len(expected):
            raise RuntimeError('Unexpected IPv4 neighbor inventory')
        for want in expected:
            hits = [x for x in rows if x.get('dst') == want['dst'] and x.get('dev') == want['device']]
            if len(hits) != 1 or hits[0].get('lladdr') != want['lladdr'] or hits[0].get('state') != ['PERMANENT']:
                raise RuntimeError('Permanent neighbor readback mismatch')
        readback[role] = rows
    return readback


def initialize_neighbors(lab):
    mode = lab.neighbor_mode
    if mode not in ('dynamic_diagnostic_only','permanent'):
        raise ValueError('Unknown neighbor mode')
    entries = planned_entries(lab)
    if mode == 'permanent':
        # Add, never replace: a collision fails closed, then owned context cleanup.
        for row in entries:
            lab._ip(row['role'],'neigh','add',row['dst'],'lladdr',row['lladdr'],
                    'nud','permanent','dev',row['device'])
        readback = verify_entries(lab,entries)
    else:
        readback = {r:json.loads(lab._ip(r,'-4','-j','neigh','show').stdout) for r in lab.namespaces}
    return {'mode':mode,'entries':entries,'readback':readback,
            'scope':'Owned synthetic topology only; unchanged UDP worker, pacing, capacity and scores'}
