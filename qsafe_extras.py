"""Optional deeper Q-SAFE analysis: archives, static engines, baselines and Linux runtime maps.

No inspected sample is executed. External tools are invoked only as static scanners.
"""
from __future__ import annotations
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import tarfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_ARCHIVE_ENTRIES = 150
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_DEPTH = 2

def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def _read_bounded(stream, limit):
    data = stream.read(limit + 1)
    return data if len(data) <= limit else None

def scan_archive_bytes(data: bytes, name: str, analyser, depth: int = 0, budget: dict | None = None):
    """Inspect ZIP/TAR members in memory; never extract paths to disk."""
    if budget is None:
        budget = {"bytes": 0, "members": 0}
    output = []
    if depth > MAX_ARCHIVE_DEPTH:
        return [{"member": name, "status": "depth-limit", "error": "nested archive depth limit reached"}]
    stream = io.BytesIO(data)
    try:
        if zipfile.is_zipfile(stream):
            stream.seek(0)
            with zipfile.ZipFile(stream) as archive:
                members = archive.infolist()
                if len(members) > MAX_ARCHIVE_ENTRIES:
                    return [{"member": name, "status": "entry-limit", "error": "archive contains too many entries"}]
                for info in members:
                    if info.is_dir():
                        continue
                    budget["members"] += 1
                    if budget["members"] > MAX_ARCHIVE_ENTRIES * (MAX_ARCHIVE_DEPTH + 1):
                        output.append({"member": name, "status": "entry-limit", "error": "total nested entry limit reached"})
                        break
                    # Reject symbolic links and encrypted entries; do not trust embedded paths.
                    mode = (info.external_attr >> 16) & 0xFFFF
                    if stat.S_ISLNK(mode):
                        output.append({"member": info.filename, "status": "skipped", "error": "symbolic link entry"})
                        continue
                    if info.flag_bits & 1:
                        output.append({"member": info.filename, "status": "skipped", "error": "encrypted archive member"})
                        continue
                    if info.file_size > MAX_MEMBER_BYTES or info.file_size < 0:
                        output.append({"member": info.filename, "status": "size-limit", "error": "member exceeds size limit"})
                        continue
                    if (info.file_size and info.compress_size == 0) or (info.compress_size > 0 and info.file_size / info.compress_size > 1000):
                        output.append({"member": info.filename, "status": "ratio-limit", "error": "extreme compression ratio"})
                        continue
                    if budget["bytes"] + info.file_size > MAX_ARCHIVE_BYTES:
                        output.append({"member": info.filename, "status": "budget-limit", "error": "archive expansion budget exceeded"})
                        break
                    try:
                        with archive.open(info, "r") as member:
                            contents = _read_bounded(member, MAX_MEMBER_BYTES)
                    except (OSError, RuntimeError, zipfile.BadZipFile):
                        contents = None
                    if contents is None:
                        output.append({"member": info.filename, "status": "read-error", "error": "member could not be read within limit"})
                        continue
                    budget["bytes"] += len(contents)
                    result = analyser(contents, info.filename)
                    output.append({"member": info.filename, "status": "scanned", "analysis": result})
                    if depth < MAX_ARCHIVE_DEPTH and (zipfile.is_zipfile(io.BytesIO(contents)) or _is_tar_bytes(contents)):
                        output.extend(scan_archive_bytes(contents, info.filename, analyser, depth + 1, budget))
        elif _is_tar_bytes(data):
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                for index, info in enumerate(archive):
                    if index >= MAX_ARCHIVE_ENTRIES:
                        output.append({"member": name, "status": "entry-limit", "error": "archive contains too many entries"})
                        break
                    if not info.isfile():
                        continue
                    budget["members"] += 1
                    if budget["members"] > MAX_ARCHIVE_ENTRIES * (MAX_ARCHIVE_DEPTH + 1):
                        output.append({"member": info.name, "status": "entry-limit", "error": "total nested entry limit reached"})
                        break
                    if info.size > MAX_MEMBER_BYTES or info.size < 0 or budget["bytes"] + info.size > MAX_ARCHIVE_BYTES:
                        output.append({"member": info.name, "status": "size-limit", "error": "member or archive expansion limit"})
                        continue
                    fp = archive.extractfile(info)
                    contents = _read_bounded(fp, MAX_MEMBER_BYTES) if fp else None
                    if contents is None:
                        output.append({"member": info.name, "status": "read-error", "error": "member could not be read"})
                        continue
                    budget["bytes"] += len(contents)
                    result = analyser(contents, info.name)
                    output.append({"member": info.name, "status": "scanned", "analysis": result})
                    if depth < MAX_ARCHIVE_DEPTH and (zipfile.is_zipfile(io.BytesIO(contents)) or _is_tar_bytes(contents)):
                        output.extend(scan_archive_bytes(contents, info.name, analyser, depth + 1, budget))
    except (OSError, tarfile.TarError, zipfile.BadZipFile, EOFError):
        return [{"member": name, "status": "archive-error", "error": "archive structure is invalid or truncated"}]
    return output

def _looks_tar(data: bytes) -> bool:
    return len(data) > 265 and data[257:262] == b"ustar"

def _is_tar_bytes(data: bytes) -> bool:
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*"):
            return True
    except (tarfile.TarError, OSError, EOFError):
        return False

def _archive_paths(target: Path):
    if target.is_file():
        yield target
        return
    if target.is_dir():
        for root, dirs, files in os.walk(target, topdown=True, followlinks=False):
            dirs[:] = [name for name in dirs if name not in {".git", ".venv", "venv", "node_modules", "__pycache__"} and not (Path(root) / name).is_symlink()]
            for name in files:
                path = Path(root) / name
                if not path.is_symlink():
                    yield path

def scan_archives(target: Path, analyser):
    """Scan archive members under target without extracting them."""
    found = []
    for path in _archive_paths(target):
        try:
            if path.is_symlink() or not path.is_file():
                continue
            if path.stat().st_size > 64 * 1024 * 1024:
                continue
            data = path.read_bytes()
            if zipfile.is_zipfile(io.BytesIO(data)) or _is_tar_bytes(data):
                entries = scan_archive_bytes(data, str(path), analyser)
                for entry in entries:
                    entry["archive"] = str(path)
                    found.append(entry)
        except OSError:
            continue
    return found

def _run(argv: list[str], timeout: int = 60):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return {"error": f"timed out after {timeout}s"}
    except OSError as exc:
        return {"error": str(exc)}

def run_yara(path: Path, rules: Path):
    rules = rules.expanduser()
    if rules.is_symlink():
        return {"engine": "YARA", "status": "error", "error": "symbolic-link rules files are refused"}
    rules = rules.resolve()
    if not rules.is_file():
        return {"engine": "YARA", "status": "error", "error": "rules path must be a regular file"}
    yara = shutil.which("yara")
    if not yara:
        return {"engine": "YARA", "status": "unavailable", "error": "install YARA and retry"}
    result = _run([yara, "-N", "-w", "-a", "20", str(rules), str(path)], timeout=30)
    if result is None:
        return {"engine": "YARA", "status": "unavailable"}
    if isinstance(result, dict):
        return {"engine": "YARA", "status": "error", **result}
    if result.returncode not in (0, 1):
        return {"engine": "YARA", "status": "error", "stderr": result.stderr[-2000:]}
    matches = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return {"engine": "YARA", "status": "match" if matches else "clean", "matches": matches}

def run_clamav(path: Path):
    clamscan = shutil.which("clamscan")
    if not clamscan:
        return {"engine": "ClamAV", "status": "unavailable", "error": "install ClamAV and update signatures"}
    result = _run([clamscan, "--no-summary", "--infected", "--max-filesize=64M", "--max-scansize=128M", str(path)], timeout=90)
    if result is None:
        return {"engine": "ClamAV", "status": "unavailable"}
    if isinstance(result, dict):
        return {"engine": "ClamAV", "status": "error", **result}
    if result.returncode == 2:
        return {"engine": "ClamAV", "status": "error", "stderr": result.stderr[-2000:]}
    matches = [line.strip() for line in result.stdout.splitlines() if " FOUND" in line]
    return {"engine": "ClamAV", "status": "match" if result.returncode == 1 or matches else "clean", "matches": matches}

def run_capa(path: Path):
    capa = shutil.which("capa")
    if not capa:
        return {"engine": "capa", "status": "unavailable", "error": "install FLARE capa and retry"}
    result = _run([capa, "-j", str(path)], timeout=120)
    if result is None:
        return {"engine": "capa", "status": "unavailable"}
    if isinstance(result, dict):
        return {"engine": "capa", "status": "error", **result}
    if result.returncode != 0:
        return {"engine": "capa", "status": "error", "stderr": result.stderr[-2000:]}
    try:
        parsed = json.loads(result.stdout)
        # Preserve structured capability output; do not turn capability names into a malware verdict.
        return {"engine": "capa", "status": "analysed", "result": parsed}
    except json.JSONDecodeError:
        return {"engine": "capa", "status": "analysed", "result_text": result.stdout[:20000]}

def run_static_engines(path: Path, yara_rules: Path | None = None, clamav: bool = False, capa: bool = False):
    results = []
    if yara_rules:
        results.append(run_yara(path, yara_rules))
    if clamav:
        results.append(run_clamav(path))
    if capa:
        results.append(run_capa(path))
    return results

def hash_file(path: Path):
    if path.is_symlink():
        raise OSError("symbolic links are not followed")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("not a regular file")
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        return {"sha256": digest.hexdigest(), "size": info.st_size, "mode": stat.S_IMODE(info.st_mode)}
    finally:
        os.close(fd)

def create_baseline(root: Path, output: Path):
    root = root.expanduser().resolve()
    output = output.expanduser().resolve()
    if not root.is_dir():
        raise ValueError("baseline target must be a directory")
    records = {}
    skipped = []
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        dirs[:] = [name for name in dirs if name not in {".git", ".venv", "venv", "node_modules", "__pycache__"} and not (Path(current) / name).is_symlink()]
        for name in files:
            path = Path(current) / name
            if path.resolve() == output or path.is_symlink():
                continue
            rel = str(path.relative_to(root))
            try:
                records[rel] = hash_file(path)
            except OSError as exc:
                skipped.append({"path": rel, "error": str(exc)})
    manifest = {"format": "qsafe-baseline-v1", "created_at": _now(), "root": str(root), "files": records, "skipped": skipped}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    try:
        os.chmod(output, 0o600)
    except OSError:
        pass
    return manifest

def check_baseline(root: Path, baseline: Path):
    root = root.expanduser().resolve()
    baseline_path = baseline.expanduser().resolve()
    manifest = json.loads(baseline_path.read_text(encoding="utf-8"))
    if manifest.get("format") != "qsafe-baseline-v1":
        raise ValueError("unsupported baseline format")
    expected = manifest.get("files", {})
    current = {}
    skipped = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if name not in {".git", ".venv", "venv", "node_modules", "__pycache__"} and not (Path(directory) / name).is_symlink()]
        for name in files:
            path = Path(directory) / name
            if path.resolve() == baseline_path or path.is_symlink():
                continue
            rel = str(path.relative_to(root))
            try:
                current[rel] = hash_file(path)
            except OSError as exc:
                skipped.append({"path": rel, "error": str(exc)})
    added = sorted(current.keys() - expected.keys())
    removed = sorted(expected.keys() - current.keys())
    changed = sorted(
        name for name in current.keys() & expected.keys()
        if current[name]["sha256"] != expected[name]["sha256"]
        or current[name]["mode"] != expected[name].get("mode")
    )
    return {"root": str(root), "baseline_created_at": manifest.get("created_at"), "added": added, "removed": removed, "modified": changed, "skipped": skipped}

def linux_runtime_findings(pid: int | None = None):
    """Inspect procfs mappings; observe only, never signal or terminate processes."""
    proc = Path("/proc")
    if not proc.is_dir():
        raise OSError("Linux procfs is not available")
    pids = [str(pid)] if pid is not None else [p.name for p in proc.iterdir() if p.name.isdigit()]
    findings = []
    for value in pids:
        base = proc / value
        try:
            name = (base / "comm").read_text(errors="replace").strip()
            exe = os.readlink(base / "exe")
            cmdline = (base / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")[:500]
            lines = (base / "maps").read_text(errors="replace").splitlines()
        except (OSError, PermissionError):
            continue
        indicators = []
        for line in lines:
            fields = line.split(maxsplit=5)
            if len(fields) < 2:
                continue
            perms = fields[1]
            mapped = fields[5] if len(fields) == 6 else ""
            if "x" not in perms:
                continue
            if "w" in perms:
                indicators.append({"reason": "writable-and-executable memory mapping", "mapping": line[:500]})
            if "memfd:" in mapped:
                indicators.append({"reason": "executable memfd mapping", "mapping": line[:500]})
            if " (deleted)" in mapped:
                indicators.append({"reason": "deleted executable remains mapped", "mapping": line[:500]})
            if not mapped and perms.startswith("r-x"):
                indicators.append({"reason": "anonymous executable memory mapping (may be JIT or unpacking)", "mapping": line[:500]})
            if mapped.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
                indicators.append({"reason": "executable mapping from a temporary writable location", "mapping": line[:500]})
        # De-duplicate identical reasons/mappings.
        unique = {(x["reason"], x["mapping"]): x for x in indicators}
        if unique:
            findings.append({"pid": int(value), "name": name, "exe": exe, "cmdline": cmdline, "indicators": list(unique.values())})
    return findings

def monitor_runtime(interval: float = 3.0, pid: int | None = None, once: bool = False):
    if interval <= 0:
        raise ValueError("interval must be positive")
    seen = set()
    try:
        while True:
            for item in linux_runtime_findings(pid):
                key = (item["pid"], tuple((x["reason"], x["mapping"]) for x in item["indicators"]))
                if key not in seen:
                    seen.add(key)
                    print(json.dumps({"timestamp": _now(), **item}, ensure_ascii=False))
            if once:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Runtime observer stopped.", flush=True)
    return 0
