"""Bounded, observational UDP echo diagnostics; no retries or acceptance changes."""
import time

MAX_ERROR_DETAILS = 32


def new_echo_diagnostics():
    return {'send_calls': 0, 'max_send_seconds': 0.0,
            'error_types': {}, 'error_details': [], 'details_omitted': 0}


def send_echo_once(sock, data, source, metric, diagnostics, *, role, sequence, sent_at):
    started = time.monotonic()
    error = None
    try:
        sock.sendto(data, source)
        metric['echoed'] += 1
    except (BlockingIOError, InterruptedError, TimeoutError) as exc:
        metric['echo_errors'] += 1
        error = exc
    finished = time.monotonic()
    duration = finished - started
    diagnostics['send_calls'] += 1
    diagnostics['max_send_seconds'] = max(diagnostics['max_send_seconds'], duration)
    if error is not None:
        name = type(error).__name__
        diagnostics['error_types'][name] = diagnostics['error_types'].get(name, 0) + 1
        if len(diagnostics['error_details']) < MAX_ERROR_DETAILS:
            diagnostics['error_details'].append({
                'role': role, 'sequence': sequence, 'sent_at': sent_at,
                'echo_attempt_started_at': started, 'echo_attempt_finished_at': finished,
                'elapsed_seconds': duration, 'error_type': name,
                'errno': error.errno, 'message': str(error)})
        else:
            diagnostics['details_omitted'] += 1
