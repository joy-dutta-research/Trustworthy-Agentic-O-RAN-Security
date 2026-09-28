import json
from pathlib import Path
import socket
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
sys.path.insert(0,str(ROOT/'src'))
from oran_trust_boundary import neighbor_transport as n
from oran_trust_boundary.stable_linux_lab import verify_netem
from transport_observer import decode_messages,udp_queue_rows
import run_transport_matrix as matrix


class Lab:
    prefix='orcl-0123456789ab'
    neighbor_mode='permanent'
    def __init__(self):
        self.namespaces={r:self.prefix+'-'+r for r in ('legitimate','suspect','router','server')}
        self._owned=list(self.namespaces.values());self.calls=[];self.rows={r:[] for r in self.namespaces}
        self.topology={r:{'links':[{'ifname':dev,'address':'02:00:00:00:00:'+f'{i:02x}'} for dev,i in pairs]}
            for r,pairs in {'legitimate':[('client0',1)],'suspect':[('client0',2)],
                           'router':[('legit0',3),('suspect0',4),('server0',5)],'server':[('server0',6)]}.items()}
    def _require_active(self):pass
    def verify_isolation(self):return self.topology
    def _ip(self,role,*args):
        self.calls.append((role,args))
        if args[0:2]==('neigh','add'):
            self.rows[role].append({'dst':args[2],'lladdr':args[4],'state':['PERMANENT'],'dev':args[-1]})
        return SimpleNamespace(stdout=json.dumps(self.rows[role]))


class NeighborTests(unittest.TestCase):
    def test_exact_six_owned_entries(self):
        lab=Lab();record=n.initialize_neighbors(lab)
        self.assertEqual(len(record['entries']),6)
        self.assertEqual(len([x for x in lab.calls if x[1][:2]==('neigh','add')]),6)
        self.assertEqual(record['entries'][4]['lladdr'],'02:00:00:00:00:05')
    def test_unowned_namespace_refused_before_mutation(self):
        for change in ('prefix','namespaces','owned','duplicate'):
            lab=Lab()
            if change=='prefix':lab.prefix='host'
            if change=='namespaces':lab.namespaces['server']='production'
            if change=='owned':lab._owned.pop()
            if change=='duplicate':lab._owned.append(lab._owned[0])
            with self.assertRaises(RuntimeError):n.initialize_neighbors(lab)
            self.assertEqual(lab.calls,[])
    def test_malformed_mac_rejected(self):
        for mac in ('ff:ff:ff:ff:ff:ff','00:00:00:00:00:00','x','01:00:00:00:00:01'):
            lab=Lab();lab.topology['router']['links'][0]['address']=mac
            with self.assertRaises(RuntimeError):n.initialize_neighbors(lab)
            self.assertEqual(lab.calls,[])
    def test_mismatch_state_address_and_extra_refused(self):
        for change in ('state','lladdr','extra'):
            lab=Lab();record=n.initialize_neighbors(lab)
            if change=='extra':lab.rows['server'].append(dict(lab.rows['server'][0]))
            else:lab.rows['server'][0][change]=['REACHABLE'] if change=='state' else '02:ff:ff:ff:ff:ff'
            with self.assertRaises(RuntimeError):n.verify_entries(lab,record['entries'])
    def test_dynamic_diagnostic_does_not_mutate_neighbors(self):
        lab=Lab();lab.neighbor_mode='dynamic_diagnostic_only'
        n.initialize_neighbors(lab)
        self.assertEqual(len(lab.calls),4)
        self.assertTrue(all(args==('-4','-j','neigh','show') for _,args in lab.calls))
    def test_unknown_mode_rejected(self):
        lab=Lab();lab.neighbor_mode='permanant'
        with self.assertRaises(ValueError):n.initialize_neighbors(lab)
        self.assertEqual(lab.calls,[])
    def test_isolation_failure_prevents_mutation(self):
        lab=Lab()
        with patch.object(lab,'verify_isolation',side_effect=RuntimeError('Unexpected route')):
            with self.assertRaises(RuntimeError):n.initialize_neighbors(lab)
        self.assertEqual(lab.calls,[])


def message(state=32,kind=28):
    attr=struct.pack('=HH',8,1)+socket.inet_aton('10.203.3.1')
    data=struct.pack('=BBHiHBB',socket.AF_INET,0,0,7,state,0,1)+attr
    return struct.pack('=IHHII',16+len(data),kind,0,0,0)+data


class ObserverTests(unittest.TestCase):
    def test_neighbor_transition_decode(self):
        rows=decode_messages(message(8)+message(16)+message(32)+message(1))
        self.assertEqual([r['states'] for r in rows],[['DELAY'],['PROBE'],['FAILED'],['INCOMPLETE']])
        self.assertTrue(all(r['dst']=='10.203.3.1' and r['ifindex']==7 for r in rows))
    def test_permanent_and_delete(self):
        self.assertEqual(decode_messages(message(128,29))[0]['operation'],'delete')
        self.assertEqual(decode_messages(message(128))[0]['states'],['PERMANENT'])
    def test_truncation_rejected(self):
        value=message()
        for i in range(1,len(value)):
            with self.assertRaises(ValueError):decode_messages(value[:i])
    def test_kernel_error_rejected(self):
        value=struct.pack('=IHHIIi',20,2,0,1,0,-105)
        with self.assertRaises(OSError):decode_messages(value)
    def test_overrun_and_interrupted_dump_rejected(self):
        for kind,flags in ((4,0),(3,0x10)):
            with self.assertRaises(RuntimeError):decode_messages(struct.pack('=IHHII',16,kind,flags,1,0))
    def test_actual_bottleneck_readback(self):
        rows=[{'kind':'netem','root':True,'options':{'limit':30,'delay':{'delay':0.005,'jitter':0,'correlation':0},
              'rate':{'rate':125000,'packetoverhead':0,'cellsize':0,'celloverhead':0},'ecn':False,'gap':0}}]
        self.assertEqual(verify_netem(rows,1000),rows)
        with self.assertRaises(RuntimeError):verify_netem(rows,10000)
        rows[0]['options']['loss']=0.1
        with self.assertRaises(RuntimeError):verify_netem(rows,1000)
    def test_udp_queue_decode(self):
        rows=udp_queue_rows('header\n 1: 0203CB0A:4A93 00000000:0000 07 00034000:00000020 00:00000000 00000000 0 0 1234 2 0000000000 3\n')
        self.assertEqual(rows,[{'tx_queue_bytes':212992,'rx_queue_bytes':32,'inode':1234,'drops':3}])
    def test_udp_wrong_binding_refused(self):
        with self.assertRaises(ValueError):udp_queue_rows('h\n1: 0100007F:4A93 0:0 07 0:0 0 0 0 0 1 0\n')
    def test_fixed_paired_budget(self):
        jobs=matrix.fixed_jobs()
        self.assertEqual(len(jobs),24)
        self.assertEqual(sum(j['mode']=='permanent' for j in jobs),12)
        for i in range(0,24,2):
            self.assertEqual(jobs[i]['method'],jobs[i+1]['method'])
            self.assertEqual(jobs[i]['replicate'],jobs[i+1]['replicate'])
            self.assertNotEqual(jobs[i]['mode'],jobs[i+1]['mode'])
    def test_unknown_failure_not_tolerated(self):
        with self.assertRaisesRegex(ValueError,'pacing'):
            matrix.validate_dynamic_failure(Path('unused'),ValueError('pacing'))


if __name__=='__main__':unittest.main()
