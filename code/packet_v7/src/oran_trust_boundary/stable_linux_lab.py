"""Versioned transport adapter; delivered LinuxLab and scientific core unchanged."""
import json
from .closed_loop_lab import LinuxLab
from .neighbor_transport import initialize_neighbors,verify_entries


def verify_netem(rows,capacity):
    expected={'limit':30,'delay':{'delay':0.005,'jitter':0,'correlation':0},
              'rate':{'rate':capacity*1000//8,'packetoverhead':0,'cellsize':0,'celloverhead':0},
              'ecn':False,'gap':0}
    if not isinstance(rows,list) or len(rows)!=1 or rows[0].get('kind')!='netem' or rows[0].get('root') is not True or rows[0].get('options')!=expected:
        raise RuntimeError('Actual bottleneck readback differs from declared topology')
    return rows


class StableLinuxLab(LinuxLab):
    neighbor_mode='permanent'

    def __enter__(self):
        super().__enter__()
        try:
            self.neighbor_receipt=initialize_neighbors(self)
            self.neighbor_receipt['bottleneck']=verify_netem(json.loads(self._tc('-j','-s','qdisc','show','dev','server0').stdout),self.capacity_kbit)
            with (self.output_dir/'neighbor_setup.json').open('x',encoding='utf-8') as f:
                json.dump(self.neighbor_receipt,f,indent=2,allow_nan=False)
            return self
        except BaseException:
            self._cleanup()
            raise

    def start_traffic(self,**kwargs):
        if self.neighbor_mode=='permanent':verify_entries(self,self.neighbor_receipt['entries'])
        return super().start_traffic(**kwargs)

    def finish(self):
        result=super().finish()
        verify_netem(json.loads(self._tc('-j','-s','qdisc','show','dev','server0').stdout),self.capacity_kbit)
        if self.neighbor_mode=='permanent':
            readback=verify_entries(self,self.neighbor_receipt['entries'])
            with (self.output_dir/'neighbor_final.json').open('x',encoding='utf-8') as f:
                json.dump(readback,f,indent=2,allow_nan=False)
        return result
