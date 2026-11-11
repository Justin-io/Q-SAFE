#!/usr/bin/env python3
"""Q-SAFE local-first static malware triage and reversible quarantine."""
from __future__ import annotations
import argparse, errno, hashlib, json, math, os, re, shutil, stat, struct, sys, time, uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.1.0"
MAX_FILE_BYTES = 64 * 1024 * 1024
STORE = Path.home() / ".local/share/qsafe/quarantine"
SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", "proc", "sys", "dev", "run"}
SCRIPTS = {".py", ".pyw", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".js", ".vbs", ".php", ".pl", ".rb"}

SCRIPT_RULES = [
 (rb"\bbase64\s*\.\s*b64decode\s*\(", 8, "base64 decoding"),
 (rb"\bmarshal\s*\.\s*loads?\s*\(", 10, "serialized code loading"),
 (rb"\b(?:eval|exec)\s*\(", 8, "dynamic code execution"),
 (rb"\bshell\s*=\s*True", 6, "shell-enabled subprocess"),
 (rb"(?:/dev/tcp/|socket\.connect\s*\(|connect_ex\s*\()", 12, "outbound socket or reverse-shell primitive"),
 (rb"\b(?:crontab|systemctl\s+enable|schtasks|RunOnce|CurrentVersion\\Run)\b", 8, "persistence-related command or key"),
 (rb"(?:curl|wget)\b[^;\n]{0,180}\|\s*(?:sh|bash)\b", 12, "download-and-execute shell pipeline"),
 (rb"\b(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|ptrace|process_vm_writev)\b", 10, "process injection or manipulation primitive"),
 (rb"\b(?:mprotect|VirtualProtect)\b", 4, "runtime memory permission change"),
 (rb"\b(?:keylogger|credential theft|dump passwords|browser cookies)\b", 10, "credential-access terminology"),
]
BINARY_RULES = [
 (rb"\b(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtWriteVirtualMemory)\b", 10, "process injection API"),
 (rb"\b(?:URLDownloadToFile|WinHttpOpen|InternetOpenUrl|HttpSendRequest)\b", 5, "network communication API"),
 (rb"\b(?:RegSetValueEx|CreateService|StartService|SetWindowsHookEx)\b", 5, "persistence or system-modification API"),
 (rb"\b(?:ptrace|process_vm_writev|memfd_create)\b", 8, "Linux process manipulation primitive"),
 (rb"\b(?:mmap|mprotect|VirtualProtect)\b", 3, "memory mapping/protection API"),
 (rb"\b(?:execve|system|popen|WinExec|ShellExecute)\b", 2, "process execution API"),
 (rb"\b(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess)\b", 4, "anti-analysis/debugger check"),
 (rb"\b(?:GetProcAddress|LoadLibraryA|LdrGetProcedureAddress|dlsym|dlopen)\b", 6, "dynamic API resolution"),
 (rb"\b(?:UPX0|UPX1|MPRESS1|\.aspack|themida)\b", 10, "known packer marker"),
]

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    return -sum((n / len(data)) * math.log2(n / len(data)) for n in counts.values())

def unpack(fmt, data, offset):
    try:
        size = struct.calcsize(fmt)
        return struct.unpack_from(fmt, data, offset) if 0 <= offset <= len(data)-size else None
    except (struct.error, TypeError):
        return None

def file_format(data: bytes) -> str:
    if data.startswith(b"MZ"): return "PE/DOS executable candidate"
    if data.startswith(b"\x7fELF"): return "ELF executable/object"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"): return "Mach-O/Fat Mach-O"
    if data.startswith(b"#!"): return "script"
    if data and b"\0" not in data[:4096]: return "text/data"
    return "unknown binary/data"

def inspect_pe(data: bytes):
    hits = []
    pe_ptr = unpack("<I", data, 0x3c)
    if not data.startswith(b"MZ") or not pe_ptr: return hits
    pe = pe_ptr[0]
    if pe > len(data)-24 or data[pe:pe+4] != b"PE\0\0": return hits
    coff = unpack("<HHIIIHH", data, pe+4)
    if not coff: return hits
    nsec, opt_size = coff[1], coff[5]
    if nsec > 96:
        return [(12, "implausibly large PE section table")]
    opt = pe+24
    magic = unpack("<H", data, opt)
    if not magic: return hits
    dirs = opt + (96 if magic[0] == 0x10b else 112 if magic[0] == 0x20b else opt_size)
    table = opt+opt_size
    end_data, high_entropy_sections = 0, 0
    sections = []
    entry_rva = unpack("<I", data, opt+16)
    for i in range(nsec):
        off = table+i*40
        if off+40 > len(data):
            hits.append((8, "truncated PE section table"))
            break
        name = data[off:off+8].rstrip(b"\0").decode("ascii", "replace")
        v = unpack("<IIIIIIHHI", data, off+8)
        if not v: continue
        va, vsize, raw, rawptr, flags = v[1], v[0], v[2], v[3], v[8]
        section_entropy = 0.0
        if raw and rawptr < len(data):
            sample = data[rawptr:min(len(data), rawptr+raw)]
            section_entropy = entropy(sample) if sample else 0.0
            if len(sample) >= 4096 and section_entropy >= 7.35:
                high_entropy_sections += 1
            end_data = max(end_data, rawptr+raw)
        sections.append((va, max(vsize, raw), rawptr, raw, flags, name, section_entropy))
        if flags & 0x20000000 and flags & 0x80000000:
            hits.append((12, f"PE section {name or '<unnamed>'} is writable and executable"))
        if name.lower() in {".upx0", ".upx1", ".aspack", ".packed", "themida"}:
            hits.append((9, f"PE section name suggests packing: {name}"))
    if high_entropy_sections:
        hits.append((12, f"{high_entropy_sections} PE section(s) have high entropy"))
    if entry_rva and entry_rva[0]:
        entry_sections = [section for section in sections if section[0] <= entry_rva[0] < section[0] + section[1]]
        if not entry_sections:
            hits.append((8, "PE entry point does not map to a declared section"))
        else:
            entry_section = entry_sections[0]
            if not (entry_section[4] & 0x20000000):
                hits.append((10, f"PE entry point resides in non-executable section {entry_section[5] or '<unnamed>'}"))
            if entry_section[6] >= 7.35 and entry_section[3] >= 4096:
                hits.append((8, f"PE entry point resides in high-entropy section {entry_section[5] or '<unnamed>'}"))
    if len(data)-end_data > 4096:
        hits.append((5, "sizeable PE overlay after section data"))
    imp = unpack("<II", data, dirs+8)
    if imp and imp[0] and imp[1]:
        mapped = any(section[0] <= imp[0] < section[0]+section[1] for section in sections)
        if not mapped: hits.append((4, "PE import directory RVA does not map to a section"))
    return hits

def inspect_elf(data: bytes):
    hits = []
    if len(data) < 20 or data[:4] != b"\x7fELF": return hits
    cls, enc = data[4], data[5]
    if cls not in (1,2) or enc not in (1,2): return [(8, "invalid ELF class or byte order")]
    endian = "<" if enc == 1 else ">"
    if cls == 2:
        phoff, entsz, n = unpack(endian+"Q", data, 32), unpack(endian+"H", data, 54), unpack(endian+"H", data, 56)
    else:
        phoff, entsz, n = unpack(endian+"I", data, 28), unpack(endian+"H", data, 42), unpack(endian+"H", data, 44)
    if phoff and entsz and n and n[0] <= 256:
        ph_format = endian + ("IIQQQQQQ" if cls == 2 else "IIIIIIII")
        for i in range(n[0]):
            fields = unpack(ph_format, data, phoff[0]+i*entsz[0])
            if not fields:
                break
            p_type = fields[0]
            p_flags = fields[1] if cls == 2 else fields[6]
            if p_type == 1 and (p_flags & 3) == 3:
                hits.append((12, "ELF load segment is writable and executable"))
                break
    return hits

def analyse_bytes(data: bytes, filename: str = ""):
    hits, score = [], 0
    fmt, ext = file_format(data), Path(filename).suffix.lower()
    def add(points, reason, category="static heuristic"):
        nonlocal score
        hits.append({"points": points, "reason": reason, "category": category})
        score += points
    for points, reason in (inspect_pe(data) if data.startswith(b"MZ") else inspect_elf(data) if data.startswith(b"\x7fELF") else []):
        add(points, reason, "executable structure")
    if data and (b"\0" not in data[:8192] or ext in SCRIPTS):
        for pattern, points, label in SCRIPT_RULES:
            if re.search(pattern, data, re.I | re.S):
                add(points, label, "script/content indicator")
    strings = b"\n".join(re.findall(rb"[\x20-\x7e]{5,}", data)[:5000])
    for pattern, points, label in BINARY_RULES:
        if re.search(pattern, strings, re.I):
            add(points, label, "embedded string/API indicator")
    ent = entropy(data)
    if len(data) >= 4096 and ent >= 7.35:
        add(10, f"high whole-file entropy ({ent:.2f}/8); compression or encryption is possible", "packing indicator")
    if len(data) >= 1024 and ent >= 7.75:
        add(5, "extremely high whole-file entropy", "packing indicator")
    low = strings.lower()
    if any(marker in low for marker in (b"upx!", b"upx0", b"upx1")):
        add(10, "UPX-like packer marker in embedded strings", "packing indicator")
    packing = sum(x["points"] for x in hits if x["category"] == "packing indicator")
    executable = fmt.startswith(("PE", "ELF", "Mach-O"))
    structural_anomaly = any(
        marker in item["reason"].lower()
        for item in hits
        for marker in ("writable and executable", "section name suggests packing", "overlay", "import directory")
    )
    dynamic_resolution = any(
        marker in strings.lower()
        for marker in (b"getprocaddress", b"loadlibrarya", b"ldrloaddll", b"dlsym", b"dlopen")
    )
    packer_marker = any(marker in strings.lower() for marker in (b"upx!", b"upx0", b"upx1", b"mpress", b"themida"))
    entropy_signal = ent >= 7.35 or any("high entropy" in item["reason"].lower() for item in hits)
    # Require more than entropy: an executable plus an independent structural,
    # dynamic-resolution or known-packer clue. This is still a candidate only.
    polymorphic = len(data) >= 4096 and executable and entropy_signal and (structural_anomaly or dynamic_resolution or packer_marker)
    if polymorphic:
        add(12, "packed/obfuscated executable profile: possible polymorphic or protected payload; not proof of malware", "polymorphic candidate")
    score = min(score, 100)
    verdict = "high-risk" if score >= 70 else "suspicious" if score >= 40 else "review" if score >= 20 else "no-known-indicators"
    return {
        "format": fmt, "size": len(data), "entropy": round(ent, 3), "score": score,
        "verdict": verdict, "polymorphic_candidate": polymorphic, "evidence": hits,
        "limitations": [
            "Static heuristics cannot prove a file malicious or benign.",
            "High entropy also occurs in legitimate compression, encryption, installers and media.",
            "Polymorphic-candidate is a triage lead, not a malware verdict."
        ]
    }

def scan_file(path: Path):
    record = {"path": str(path), "scanned_at": now(), "sha256": None, "size": None, "status": "error", "analysis": None, "error": None}
    try:
        if path.is_symlink(): raise OSError("symbolic links are not followed")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode): raise OSError("not a regular file")
            record["size"] = info.st_size
            if info.st_size > MAX_FILE_BYTES:
                record.update(status="skipped", error=f"file exceeds {MAX_FILE_BYTES} byte limit")
                return record
            parts, digest = [], hashlib.sha256()
            while True:
                block = os.read(fd, 1024*1024)
                if not block: break
                parts.append(block); digest.update(block)
            data = b"".join(parts)
            if len(data) != info.st_size: raise OSError("file changed while being read")
            record["sha256"] = digest.hexdigest()
            record["analysis"] = analyse_bytes(data, path.name)
            try:
                import ssdeep
                record["fuzzy_hash"] = {"algorithm": "ssdeep", "value": ssdeep.hash(data)}
            except ImportError:
                record["fuzzy_hash"] = None
            record["status"] = "scanned"
        finally:
            os.close(fd)
    except OSError as exc:
        record["error"] = str(exc)
    return record

def iter_files(target: Path):
    if target.is_symlink(): return
    if target.is_file():
        yield target
    elif target.is_dir():
        for root, dirs, files in os.walk(target, topdown=True, followlinks=False):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not (Path(root)/d).is_symlink()]
            for name in files:
                item = Path(root)/name
                if not item.is_symlink(): yield item

def scan_target(target: Path):
    files, skipped, total_bytes = [], [], 0
    for index, path in enumerate(iter_files(target)):
        if index >= 20000:
            skipped.append({"path": str(path), "error": "maximum file count reached"})
            break
        item = scan_file(path)
        if item["status"] == "scanned":
            if total_bytes + item["size"] > 512 * 1024 * 1024:
                skipped.append({"path": str(path), "error": "total scan byte budget reached"})
                break
            total_bytes += item["size"]
            files.append(item)
        else:
            skipped.append({"path": str(path), "error": item.get("error") or item["status"]})
    counts = Counter(x["analysis"]["verdict"] for x in files)
    flagged = [x for x in files if x["analysis"]["score"] >= 20]
    return {
        "tool": "Q-SAFE", "version": VERSION, "scanned_at": now(), "target": str(target),
        "summary": {"scanned": len(files), "flagged": len(flagged), "high_risk": counts["high-risk"], "suspicious": counts["suspicious"], "review": counts["review"], "errors_or_skipped": len(skipped), "bytes_scanned": total_bytes},
        "skipped": skipped,
        "files": files
    }

def _move_verified(source: Path, destination: Path, expected_sha256: str):
    source_stat = source.stat(follow_symlinks=False)
    try:
        os.replace(source, destination)
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
        # Cross-device fallback: copy into the private destination, fsync,
        # verify its digest, confirm the source did not change, then unlink.
        with source.open("rb") as src, destination.open("xb") as dst:
            shutil.copyfileobj(src, dst, length=1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
        try:
            copied = scan_file(destination)
            if copied["sha256"] != expected_sha256:
                raise OSError("copied file failed SHA-256 verification")
            current = source.stat(follow_symlinks=False)
            if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) != (source_stat.st_dev, source_stat.st_ino, source_stat.st_size, source_stat.st_mtime_ns):
                raise OSError("source changed during quarantine/restore copy")
            source.unlink()
        except Exception:
            destination.unlink(missing_ok=True)
            raise
    verified = scan_file(destination)
    if verified["sha256"] != expected_sha256:
        if not source.exists() and destination.exists():
            os.replace(destination, source)
        else:
            destination.unlink(missing_ok=True)
        raise OSError("SHA-256 verification failed")
    return verified

def quarantine_file(path: Path, store: Path = STORE, confirmed: bool = False):
    if not confirmed:
        raise PermissionError("explicit confirmation required")
    if path.is_symlink() or not path.is_file():
        raise OSError("only regular non-symlink files can be quarantined")
    before = scan_file(path)
    if before["status"] != "scanned":
        raise OSError("file could not be scanned safely")
    root = store.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    uid = str(uuid.uuid4())
    folder = root / uid
    folder.mkdir(mode=0o700)
    payload = folder / "sample.quarantined"
    manifest = {"id": uid, "original_path": str(path.absolute()), "sha256": before["sha256"], "size": before["size"], "quarantined_at": now(), "analysis": before["analysis"]}
    try:
        _move_verified(path, payload, manifest["sha256"])
        (folder / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        os.chmod(folder / "manifest.json", 0o600)
    except Exception as original_error:
        rollback_error = None
        if payload.exists() and not path.exists():
            try:
                _move_verified(payload, path, manifest["sha256"])
            except Exception as exc:
                rollback_error = exc
        if payload.exists() and not path.exists():
            # Preserve the sample in quarantine rather than deleting the only
            # verified copy if rollback cannot be completed.
            raise OSError(f"metadata/rollback failure; sample preserved at {payload}; rollback error: {rollback_error}") from original_error
        shutil.rmtree(folder, ignore_errors=True)
        raise
    return manifest

def restore_item(uid: str, store: Path = STORE, destination: Path | None = None):
    try: uuid.UUID(uid)
    except ValueError as exc: raise ValueError("invalid quarantine identifier") from exc
    root = store.expanduser().resolve()
    folder = (root/uid).resolve()
    if folder.parent != root: raise ValueError("invalid quarantine path")
    manifest = json.loads((folder/"manifest.json").read_text(encoding="utf-8"))
    payload = folder/"sample.quarantined"
    check = scan_file(payload)
    if check["sha256"] != manifest.get("sha256"): raise OSError("quarantine integrity check failed")
    target = destination or Path(manifest["original_path"])
    if target.exists() or target.is_symlink(): raise FileExistsError(f"destination already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    _move_verified(payload, target, manifest["sha256"])
    shutil.rmtree(folder)
    return target

def cmd_scan(args):
    target = Path(args.path).expanduser()
    if not target.exists():
        print(f"Path not found: {target}", file=sys.stderr)
        return 2
    report = scan_target(target)
    if args.archives:
        from qsafe_extras import scan_archives
        report["archive_members"] = scan_archives(target, analyse_bytes)
        report["summary"]["archive_members_scanned"] = sum(1 for entry in report["archive_members"] if entry.get("status") == "scanned")
        report["summary"]["archive_members_flagged"] = sum(1 for entry in report["archive_members"] if entry.get("analysis", {}).get("score", 0) >= 20)
    if args.yara_rules or args.clamav or args.capa:
        from qsafe_extras import run_static_engines
        for item in report["files"]:
            item["external_engines"] = run_static_engines(
                Path(item["path"]),
                Path(args.yara_rules) if args.yara_rules else None,
                args.clamav,
                args.capa,
            )
            for result in item["external_engines"]:
                if result["engine"] == "ClamAV" and result["status"] == "match":
                    item["analysis"]["evidence"].append({"points": 100, "reason": "ClamAV signature match: " + "; ".join(result.get("matches", [])), "category": "external antivirus"})
                    item["analysis"]["score"] = 100
                    item["analysis"]["verdict"] = "high-risk"
                elif result["engine"] == "YARA" and result["status"] == "match":
                    item["analysis"]["evidence"].append({"points": 25, "reason": "YARA rule match: " + "; ".join(result.get("matches", [])), "category": "external rule"})
                    item["analysis"]["score"] = min(100, item["analysis"]["score"] + 25)
                    if item["analysis"]["score"] >= 70:
                        item["analysis"]["verdict"] = "high-risk"
                    elif item["analysis"]["score"] >= 40:
                        item["analysis"]["verdict"] = "suspicious"
                    elif item["analysis"]["score"] >= 20:
                        item["analysis"]["verdict"] = "review"
        counts = Counter(item["analysis"]["verdict"] for item in report["files"])
        report["summary"].update({
            "flagged": sum(1 for item in report["files"] if item["analysis"]["score"] >= 20),
            "high_risk": counts["high-risk"],
            "suspicious": counts["suspicious"],
            "review": counts["review"],
        })
    s = report["summary"]
    print(f"Q-SAFE {VERSION} | {target}")
    print(f"Scanned {s['scanned']} | Flagged {s['flagged']} | High risk {s['high_risk']} | Skipped {s['errors_or_skipped']}")
    for item in sorted(report["files"], key=lambda x: x["analysis"]["score"], reverse=True):
        a = item["analysis"]
        if a["score"] >= 20:
            suffix = " [POLYMORPHIC CANDIDATE]" if a["polymorphic_candidate"] else ""
            print(f"[{a['verdict'].upper():10}] {a['score']:3}/100 {item['path']}{suffix}")
            for hit in a["evidence"]:
                print(f"    +{hit['points']:02} {hit['reason']}")
            for engine in item.get("external_engines", []):
                if engine["status"] in {"match", "error", "unavailable"}:
                    print(f"    [{engine['engine']}] {engine['status']}")
    if args.json:
        out = Path(args.json).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Report: {out}")
    archive_high = any(entry.get("analysis", {}).get("score", 0) >= 70 for entry in report.get("archive_members", []))
    if report.get("archive_members"):
        for entry in report["archive_members"]:
            analysis = entry.get("analysis")
            if analysis and analysis.get("score", 0) >= 20:
                print(f"[ARCHIVE {analysis['verdict'].upper()}] {entry.get('archive')} :: {entry['member']} ({analysis['score']}/100)")
    return 1 if s["high_risk"] or archive_high else 0

def cmd_quarantine(args):
    path = Path(args.path).expanduser()
    item = scan_file(path)
    if item["status"] != "scanned": print(f"Refusing quarantine: {item['error']}", file=sys.stderr); return 2
    a = item["analysis"]
    print(f"{path}: {a['verdict']} ({a['score']}/100)")
    for hit in a["evidence"]: print(" - "+hit["reason"])
    if not args.yes and input("Move into quarantine? Type QUARANTINE to confirm: ") != "QUARANTINE":
        print("Cancelled; unchanged."); return 0
    result = quarantine_file(path, Path(args.store), True)
    print(f"Quarantined and SHA-256 verified. ID: {result['id']}")
    return 0

def cmd_restore(args):
    print("Restored:", restore_item(args.id, Path(args.store), Path(args.to) if args.to else None)); return 0

def cmd_list(args):
    root = Path(args.store).expanduser()
    if not root.exists(): print("Quarantine is empty."); return 0
    for f in root.glob("*/manifest.json"):
        try:
            m = json.loads(f.read_text(encoding="utf-8"))
            print(f"{m['id']}  {m['size']} bytes  {m['original_path']}  SHA256={m['sha256']}")
        except (OSError, KeyError, json.JSONDecodeError): print("Unreadable record:", f, file=sys.stderr)
    return 0

def cmd_monitor(args):
    root = Path(args.path).expanduser()
    if not root.is_dir(): print("Monitor target must be a directory.", file=sys.stderr); return 2
    log = Path(args.log).expanduser(); log.parent.mkdir(parents=True, exist_ok=True)
    def snapshot():
        data = {}
        for p in iter_files(root):
            try:
                st = p.stat(follow_symlinks=False); data[str(p)] = (st.st_size, st.st_mtime_ns)
            except OSError: pass
        return data
    previous = snapshot()
    print(f"Q-SAFE polling monitor: {root}; Ctrl-C to stop.")
    try:
        while True:
            time.sleep(args.interval); current = snapshot()
            for name, stamp in current.items():
                if name not in previous or previous[name] != stamp:
                    result = scan_file(Path(name))
                    event = {"timestamp": now(), "event": "created" if name not in previous else "modified", "result": result}
                    with log.open("a", encoding="utf-8") as fp: fp.write(json.dumps(event)+"\n")
                    if result["analysis"] and result["analysis"]["score"] >= 20:
                        print(f"[ALERT] {result['analysis']['verdict']} {result['analysis']['score']}/100: {name}")
            for name in previous.keys()-current.keys():
                with log.open("a", encoding="utf-8") as fp: fp.write(json.dumps({"timestamp":now(),"event":"deleted-or-moved","path":name})+"\n")
            previous = current
    except KeyboardInterrupt: print("\nMonitor stopped.")
    return 0


def cmd_baseline_create(args):
    from qsafe_extras import create_baseline
    manifest = create_baseline(Path(args.path), Path(args.output))
    print(f"Baseline created: {args.output} | files: {len(manifest['files'])} | skipped: {len(manifest['skipped'])}")
    return 0

def cmd_baseline_check(args):
    from qsafe_extras import check_baseline
    result = check_baseline(Path(args.path), Path(args.baseline))
    print(f"Integrity check: {result['root']}")
    for label in ("added", "modified", "removed"):
        values = result[label]
        print(f"{label.title()}: {len(values)}")
        for value in values[:100]:
            print(f"  {value}")
    if result["skipped"]:
        print(f"Skipped/unreadable: {len(result['skipped'])}")
    return 1 if result["added"] or result["modified"] or result["removed"] else 0

def cmd_runtime_watch(args):
    from qsafe_extras import monitor_runtime
    return monitor_runtime(args.interval, args.pid, args.once)


def cmd_similarity(args):
    try:
        import ssdeep
    except ImportError:
        print("ssdeep Python module is not installed. Install the optional ssdeep package and system libfuzzy.", file=sys.stderr)
        return 2
    first_path = Path(args.first).expanduser()
    second_path = Path(args.second).expanduser()
    first = scan_file(first_path)
    second = scan_file(second_path)
    if first["status"] != "scanned" or second["status"] != "scanned":
        print("Both inputs must be readable regular files within the scan size limit.", file=sys.stderr)
        return 2
    left = first.get("fuzzy_hash", {}).get("value") if first.get("fuzzy_hash") else ssdeep.hash(first_path.read_bytes())
    right = second.get("fuzzy_hash", {}).get("value") if second.get("fuzzy_hash") else ssdeep.hash(second_path.read_bytes())
    score = ssdeep.compare(left, right)
    print(f"ssdeep similarity: {score}/100")
    print("Interpretation: similarity can support sample clustering; it does not prove shared lineage or maliciousness.")
    return 0

def parser():
    p = argparse.ArgumentParser(prog="qsafe", description="Q-SAFE static malware triage and reversible quarantine")
    p.add_argument("--version", action="version", version=f"Q-SAFE {VERSION}")
    sub = p.add_subparsers(dest="command", required=True)
    x = sub.add_parser("scan", help="read-only static scan")
    x.add_argument("path")
    x.add_argument("--json")
    x.add_argument("--archives", action="store_true", help="inspect bounded ZIP/TAR members without extracting them")
    x.add_argument("--yara-rules", help="run YARA with this local source rules file")
    x.add_argument("--clamav", action="store_true", help="run local ClamAV signatures if clamscan is installed")
    x.add_argument("--capa", action="store_true", help="run Mandiant capa static capability analysis if installed")
    x.set_defaults(func=cmd_scan)
    x = sub.add_parser("quarantine", help="explicitly quarantine one file")
    x.add_argument("path"); x.add_argument("--store", default=str(STORE)); x.add_argument("--yes", action="store_true"); x.set_defaults(func=cmd_quarantine)
    x = sub.add_parser("restore", help="restore by quarantine ID")
    x.add_argument("id"); x.add_argument("--store", default=str(STORE)); x.add_argument("--to"); x.set_defaults(func=cmd_restore)
    x = sub.add_parser("quarantine-list", help="list quarantined samples")
    x.add_argument("--store", default=str(STORE)); x.set_defaults(func=cmd_list)
    x = sub.add_parser("monitor", help="poll a directory for file changes")
    x.add_argument("path"); x.add_argument("--interval", type=float, default=3.0); x.add_argument("--log", default=str(Path.home()/".local/state/qsafe/events.jsonl")); x.set_defaults(func=cmd_monitor)
    x = sub.add_parser("similarity", help="compare two files with optional ssdeep fuzzy hashing")
    x.add_argument("first"); x.add_argument("second"); x.set_defaults(func=cmd_similarity)
    x = sub.add_parser("baseline-create", help="create a SHA-256 file integrity baseline")
    x.add_argument("path"); x.add_argument("--output", default=str(Path.home()/".local/state/qsafe/baseline.json")); x.set_defaults(func=cmd_baseline_create)
    x = sub.add_parser("baseline-check", help="compare a directory against a stored baseline")
    x.add_argument("path"); x.add_argument("--baseline", default=str(Path.home()/".local/state/qsafe/baseline.json")); x.set_defaults(func=cmd_baseline_check)
    x = sub.add_parser("runtime-watch", help="observe Linux executable memory mappings (no process termination)")
    x.add_argument("--pid", type=int); x.add_argument("--interval", type=float, default=3.0); x.add_argument("--once", action="store_true"); x.set_defaults(func=cmd_runtime_watch)
    return p

def main(argv=None):
    args = parser().parse_args(argv)
    if getattr(args, "interval", 1) <= 0: print("interval must be positive", file=sys.stderr); return 2
    try: return int(args.func(args))
    except (OSError, ValueError, PermissionError, json.JSONDecodeError) as exc: print("Q-SAFE error:", exc, file=sys.stderr); return 2

if __name__ == "__main__":
    raise SystemExit(main())
