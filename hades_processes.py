"""Terminación comprobada de procesos y sus descendientes."""
import os
import subprocess


def _snapshot_descendants(pid):
    """Devuelve descendientes psutil o ``None`` si no se pueden inventariar."""
    try:
        import psutil
    except ImportError:
        return None
    try:
        return psutil.Process(pid).children(recursive=True)
    except psutil.NoSuchProcess:
        return []
    except (psutil.AccessDenied, OSError):
        return None


def _psutil_alive(process):
    try:
        return process.is_running() and process.status() != "zombie"
    except Exception:
        return False


def _stop_descendants(descendants, timeout):
    if descendants is None:
        return False
    try:
        import psutil
    except ImportError:
        return False
    alive = [process for process in reversed(descendants) if _psutil_alive(process)]
    for process in alive:
        try:
            process.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            pass
    _, alive = psutil.wait_procs(alive, timeout=timeout)
    for process in alive:
        try:
            process.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            pass
    _, alive = psutil.wait_procs(alive, timeout=timeout)
    return not any(_psutil_alive(process) for process in alive)


def _wait_root(process, action, timeout):
    try:
        action()
    except Exception:
        pass
    try:
        process.wait(timeout=timeout)
    except (subprocess.TimeoutExpired, TimeoutError, OSError):
        return process.poll() is not None
    except Exception:
        return process.poll() is not None
    return process.poll() is not None


def terminate_process_tree(
    process,
    *,
    timeout=3,
    taskkill_runner=subprocess.run,
    platform_name=os.name,
):
    """Termina un ``Popen`` y comprueba el árbol conocido.

    En Windows se intenta primero ``taskkill /F /T`` sin shell y se verifica su
    ``returncode``. Si falla o el proceso sigue vivo, se escala de
    ``terminate`` a ``kill`` con ``wait`` en cada etapa. Los descendientes se
    inventarían antes del corte mediante psutil para poder comprobarlos incluso
    si el PID padre desaparece.
    """
    if process is None:
        return True
    try:
        pid = int(process.pid)
    except Exception:
        return False

    descendants = _snapshot_descendants(pid)
    if process.poll() is not None:
        try:
            process.wait(timeout=timeout)
        except Exception:
            pass
        descendants_stopped = _stop_descendants(descendants, timeout)
        return descendants_stopped if descendants is not None else False

    taskkill_ok = False
    if platform_name == "nt":
        try:
            result = taskkill_runner(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            taskkill_ok = result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            taskkill_ok = False
        if taskkill_ok:
            try:
                process.wait(timeout=timeout)
            except (subprocess.TimeoutExpired, TimeoutError, OSError):
                pass

    descendants_stopped = _stop_descendants(descendants, timeout)
    if process.poll() is None:
        _wait_root(process, process.terminate, timeout)
    if process.poll() is None:
        _wait_root(process, process.kill, timeout)

    root_stopped = process.poll() is not None
    if descendants is None:
        # Sin inventario sólo taskkill /T permite afirmar que el árbol murió.
        tree_stopped = taskkill_ok
    else:
        tree_stopped = descendants_stopped and not any(
            _psutil_alive(child) for child in descendants
        )
    return root_stopped and tree_stopped
