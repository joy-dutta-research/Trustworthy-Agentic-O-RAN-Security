import importlib.util
from pathlib import Path
import socket
import unittest
from unittest.mock import Mock, patch

PATH = Path(__file__).resolve().parents[1]/'scripts/echo_diagnostic_helpers.py'
spec = importlib.util.spec_from_file_location('echo_diagnostic_helpers_test', PATH)
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)


class EchoLoggingTests(unittest.TestCase):
    def call(self, error=None):
        sock=Mock()
        if error is not None:sock.sendto.side_effect=error
        metric={'echoed':0,'echo_errors':0}
        record=diag.new_echo_diagnostics()
        with patch.object(diag.time,'monotonic',side_effect=[100.0,100.05]):
            diag.send_echo_once(sock,b'x',('10.203.2.2',1),metric,record,
                                role='suspect',sequence=13,sent_at=99.0)
        sock.sendto.assert_called_once_with(b'x',('10.203.2.2',1))
        return metric,record

    def test_success_changes_no_transport_counters(self):
        metric,record=self.call()
        self.assertEqual(metric,{'echoed':1,'echo_errors':0})
        self.assertEqual(record['error_details'],[])
        self.assertEqual(record['send_calls'],1)

    def test_timeout_recorded_without_retry(self):
        self.assertIs(socket.timeout,TimeoutError)
        metric,record=self.call(socket.timeout('timed out'))
        self.assertEqual(metric,{'echoed':0,'echo_errors':1})
        detail=record['error_details'][0]
        self.assertEqual(detail['error_type'],'TimeoutError')
        self.assertEqual(detail['sequence'],13)
        self.assertAlmostEqual(detail['elapsed_seconds'],0.05)

    def test_blocking_error_not_hidden(self):
        metric,record=self.call(BlockingIOError(11,'would block'))
        self.assertEqual(metric['echo_errors'],1)
        self.assertEqual(record['error_details'][0]['errno'],11)

    def test_interrupted_error_not_hidden(self):
        metric,record=self.call(InterruptedError(4,'interrupted'))
        self.assertEqual(metric['echo_errors'],1)
        self.assertEqual(record['error_types'],{'InterruptedError':1})

    def test_other_oserror_still_propagates(self):
        with self.assertRaises(ConnectionRefusedError):self.call(ConnectionRefusedError(111,'refused'))

    def test_bounded_log_counts_all_errors(self):
        sock=Mock();sock.sendto.side_effect=TimeoutError('timed out')
        metric={'echoed':0,'echo_errors':0};record=diag.new_echo_diagnostics()
        for i in range(80):
            diag.send_echo_once(sock,b'x',('10.203.2.2',1),metric,record,
                                role='suspect',sequence=i,sent_at=1.0)
        self.assertEqual(len(record['error_details']),32)
        self.assertEqual(record['details_omitted'],48)
        self.assertEqual(record['error_types'],{'TimeoutError':80})
        self.assertEqual(metric['echo_errors'],80)
        self.assertEqual(sock.sendto.call_count,80)

    def test_records_independent(self):
        a=diag.new_echo_diagnostics();b=diag.new_echo_diagnostics()
        a['error_details'].append({})
        self.assertEqual(b['error_details'],[])

    def test_frozen_scorer_still_rejects_echo_errors(self):
        import sys
        sys.path.insert(0,str(PATH.parents[1]/'src'))
        from oran_trust_boundary.closed_loop_results import score_server
        server=[{'type':'server_summary','invalid':0,'sources':{
            role:{'received':10,'received_bytes':5120,'echoed':9,'echo_errors':1}
            for role in ('legitimate','suspect')}}]
        clients={role:[{'type':'cohort_summary','sent':10,'received':9}]
                 for role in ('legitimate','suspect')}
        with self.assertRaisesRegex(ValueError,'accounting mismatch'):score_server(server,clients,20,512)


if __name__=='__main__':unittest.main()
