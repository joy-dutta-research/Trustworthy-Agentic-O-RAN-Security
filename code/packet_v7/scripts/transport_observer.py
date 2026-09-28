"""Read-only bounded neighbor events and socket queues in the server namespace."""
import json
import select
import socket
import struct
import threading
import time
from pathlib import Path

STATES = {1:'INCOMPLETE',2:'REACHABLE',4:'STALE',8:'DELAY',16:'PROBE',32:'FAILED',64:'NOARP',128:'PERMANENT'}


def decode_messages(data):
    records=[]
    offset=0
    while offset < len(data):
        if len(data)-offset < 16: raise ValueError('Truncated netlink header')
        length,kind,flags,sequence,pid=struct.unpack_from('=IHHII',data,offset)
        if length < 16 or offset+length > len(data): raise ValueError('Invalid netlink length')
        payload=data[offset+16:offset+length]
        if kind == 4 or flags & 0x10:
            raise RuntimeError('Neighbor event overrun or interrupted dump')
        if kind == 2:
            if len(payload)<4: raise ValueError('Truncated netlink error')
            error=struct.unpack_from('=i',payload)[0]
            if error: raise OSError(-error,'Neighbor netlink error')
        elif kind in (28,29):
            if len(payload)<12: raise ValueError('Truncated neighbor message')
            family,_,_,index,state,neighbor_flags,typ=struct.unpack_from('=BBHiHBB',payload)
            if family == socket.AF_INET:
                record={'kind':'neighbor','operation':'new' if kind==28 else 'delete',
                        'ifindex':index,'state_value':state,
                        'states':[name for bit,name in STATES.items() if state&bit],
                        'sequence':sequence,'flags':neighbor_flags,'type':typ}
                pos=12
                while pos < len(payload):
                    if len(payload)-pos < 4: raise ValueError('Truncated neighbor attribute')
                    size,key=struct.unpack_from('=HH',payload,pos)
                    if size<4 or pos+size>len(payload): raise ValueError('Invalid neighbor attribute')
                    value=payload[pos+4:pos+size]
                    if key==1:
                        if len(value)!=4:raise ValueError('Bad IPv4 neighbor address')
                        record['dst']=socket.inet_ntoa(value)
                    elif key==2:record['lladdr']=':'.join(f'{v:02x}' for v in value)
                    pos+=(size+3)&~3
                records.append(record)
        offset+=(length+3)&~3
    return records


def udp_queue_rows(text):
    records=[]
    for line in text.splitlines()[1:]:
        fields=line.split()
        if len(fields)<10:raise ValueError('Malformed UDP proc row')
        ip,port=fields[1].split(':')
        if int(port,16)!=19091:continue
        if ip!='0203CB0A':raise ValueError('Unexpected server UDP binding')
        tx,rx=fields[4].split(':')
        records.append({'tx_queue_bytes':int(tx,16),'rx_queue_bytes':int(rx,16),
                        'inode':int(fields[9]),'drops':int(fields[-1])})
    if len(records)>1:raise ValueError('Ambiguous server UDP socket')
    return records


class TransportObserver:
    def __init__(self,path):
        self.path=Path(path);self.stop_event=threading.Event();self.ready=threading.Event()
        self.error=None;self.count=0;self.bytes=0;self.thread=None

    def _run(self):
        try:
            with self.path.open('x',encoding='utf-8',buffering=65536) as f, socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,socket.NETLINK_ROUTE) as nl:
                def emit(value):
                    raw=json.dumps({'monotonic':time.monotonic(),**value},allow_nan=False,separators=(',',':'))+'\n'
                    self.count+=1;self.bytes+=len(raw)
                    if self.count>6000 or self.bytes>2*1024*1024:raise RuntimeError('Observer evidence budget exceeded')
                    f.write(raw)
                nl.bind((0,4)) # RTMGRP_NEIGH only; no changes to the neighbor table.
                request=struct.pack('=BBHiHBB',socket.AF_INET,0,0,0,0,0,0)
                nl.send(struct.pack('=IHHII',16+len(request),30,0x301,1,0)+request)
                next_sample=time.monotonic();deadline=next_sample+75
                emit({'kind':'observer_started','sample_period_seconds':0.05,'read_only':True})
                self.ready.set()
                while not self.stop_event.is_set():
                    now=time.monotonic()
                    if now>=deadline:raise RuntimeError('Observer lifetime exceeded')
                    if now>=next_sample:
                        emit({'kind':'udp_queue','sockets':udp_queue_rows(Path('/proc/net/udp').read_text())})
                        next_sample=now+0.05
                    if select.select([nl],[],[],max(0,min(0.05,next_sample-time.monotonic())))[0]:
                        data,_,flags,_=nl.recvmsg(65536)
                        if flags & socket.MSG_TRUNC:raise RuntimeError('Truncated neighbor event')
                        for value in decode_messages(data):emit(value)
                emit({'kind':'observer_complete'})
        except BaseException as error:
            self.error=error;self.ready.set()

    def start(self):
        self.thread=threading.Thread(target=self._run,name='bounded-neighbor-observer',daemon=True)
        self.thread.start()
        if not self.ready.wait(2):raise RuntimeError('Observer did not start')
        self.check()

    def check(self):
        if self.error:raise RuntimeError('Transport observer failed: '+repr(self.error)) from self.error

    def close(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(2)
            if self.thread.is_alive():raise RuntimeError('Observer did not stop')
        self.check()
