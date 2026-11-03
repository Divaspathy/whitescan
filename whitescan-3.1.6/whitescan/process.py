"""whitescan.process"""
import os
import select
import threading

_ACTIVE = set()
_ACTIVE_LOCK = threading.Lock()
ABORT = threading.Event()

def _register(proc):
    if proc is None:
        return
    with _ACTIVE_LOCK:
        _ACTIVE.add(proc)

def _unregister(proc):
    if proc is None:
        return
    with _ACTIVE_LOCK:
        _ACTIVE.discard(proc)

def terminate_active():
    with _ACTIVE_LOCK:
        procs = list(_ACTIVE)
    for p in procs:
        try:
            p.terminate()
        except OSError:
            pass
    for p in procs:
        try:
            p.wait(timeout=5)
        except Exception:
            try:
                p.kill()
            except OSError:
                pass

def _stop_proc(proc, timeout=5):
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
    except OSError:
        pass
    try:
        proc.wait(timeout=timeout)
    except Exception:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=2)
        except Exception:
            pass

def _iter_proc_lines(proc, poll_s=0.4):
    """Yield stdout lines from a binary-mode Popen.

    select() wakes every poll_s so ABORT is noticed while nmap is quiet.
    Do not open stdout in text mode; buffered TextIOWrapper hides data
    from select(). A process that has already exited is drained even
    if ABORT is set, so a finished scan is not thrown away.
    """
    fd = proc.stdout.fileno()
    pending = b""
    aborted = False
    while True:
        if ABORT.is_set() and proc.poll() is None:
            aborted = True
            _stop_proc(proc)
            break
        try:
            ready, _, _ = select.select([fd], [], [], poll_s)
        except (OSError, ValueError):
            break
        if not ready:
            if proc.poll() is not None:
                break
            continue
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        pending += chunk
        while b"\n" in pending:
            raw, pending = pending.split(b"\n", 1)
            yield raw.decode("utf-8", "replace")
    if pending and not aborted:
        yield pending.decode("utf-8", "replace")
    if proc.poll() is None:
        try:
            proc.wait(timeout=5)
        except Exception:
            pass

