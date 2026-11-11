"""Static, explainable file analysis. Never executes inspected content."""
from __future__ import annotations
import hashlib, math, os, re, stat
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

MAX_SAMPLE = 8 * 1024 * 1024
SUSPICIOUS_STRINGS = {
    b"curl|sh": 24, b"wget|sh": 24, b"base64 -d": 12,
    b"powershell -enc": 22, b"invoke-expression": 14,
    b"subprocess.popen": 8, b"os.system(": 8,
    b"socket.socket": 7, b"create_subprocess_shell": 12,
    b"ptrace(": 10, b"process_vm_writev": 12,
    b"/dev/shm/": 8, b"crontab": 5,
}
PACKER_MARKERS = [b"UPX!", b"MPRESS", b"ASPack", b"themida", b"VMProtect"]
SCRIPT_PATTERNS = [
    (re.compile(rb"(?:eval|exec)\s*\(\s*(?:base64|atob|FromBase64String)", re.I), 18, "obfuscated dynamic execution"),
    (re.compile(rb"chmod\s+\+x.*&&.*\./", re.I|re.S), 10, "permission-change and execution chain"),
    (re.compile(rb"rm\s+-rf\s+/(?:\s|$)", re.I), 30, "destructive root deletion command"),
    (re.compile(rb"(?:curl|wget).{0,200}(?:\.sh|\|\s*(?:bash|sh))", re.I|re.S), 14, "remote script retrieval/execution pattern"),
]
@dataclass
class Finding:
    code: str
    severity: str
    score: int
    detail: str
@dataclass
class Analysis:
    path: str
    sha256: str
    size: int
    file_type: str
    entropy: float
    score: int
    verdict: str
    findings: list[Finding]
    errors: list[str]
    def to_dict(self) -> dict[str, Any]: return asdict(self)

def entropy(data: bytes) -> float:
    if not data: return 0.0
    counts=Counter(data); n=len(data)
    return -sum((c/n)*math.log2(c/n) for c in counts.values())

def identify(data: bytes) -> str:
    if data.startswith(b"\x7fELF"): return "ELF executable"
    if data.startswith(b"MZ"): return "PE/Windows executable"
    if data.startswith(b"#!"): return "script"
    if data.startswith(b"PK\x03\x04"): return "ZIP/container"
    if data.startswith(b"\x1f\x8b"): return "GZIP/compressed"
    if b"\x00" not in data[:4096]: return "text or unknown"
    return "binary or unknown"

def analyze_file(path: str | Path) -> Analysis:
    p=Path(path); findings=[]
    try:
        st=p.lstat()
        if stat.S_ISLNK(st.st_mode):
            return Analysis(str(p),"",0,"symbolic link",0,0,"REVIEW",[],["symlink is not followed"])
        if not stat.S_ISREG(st.st_mode):
            return Analysis(str(p),"",st.st_size,"non-regular",0,0,"SKIPPED",[],["not a regular file"])
        with p.open("rb") as f: data=f.read(MAX_SAMPLE+1)
        truncated=len(data)>MAX_SAMPLE; sample=data[:MAX_SAMPLE]
        digest=hashlib.sha256(sample).hexdigest()
        file_hash=("sampled-sha256:"+digest) if truncated else digest
        typ=identify(sample); ent=entropy(sample[:1024*1024]); lower=sample.lower()
        if truncated: findings.append(Finding("SAMPLE_TRUNCATED","info",0,"Only first 8 MiB inspected; hash is sample-only"))
        if typ in ("ELF executable","PE/Windows executable"):
            findings.append(Finding("EXECUTABLE_FORMAT","info",0,f"Executable format: {typ}"))
        if ent>=7.35 and len(sample)>=4096:
            findings.append(Finding("HIGH_ENTROPY","medium",16,f"High byte entropy ({ent:.2f}/8); may indicate packing or encryption"))
        for marker in PACKER_MARKERS:
            if marker.lower() in lower: findings.append(Finding("PACKER_MARKER","medium",14,f"Known packer/protector marker: {marker.decode()}"))
        for needle,weight in SUSPICIOUS_STRINGS.items():
            if needle in lower: findings.append(Finding("SUSPICIOUS_STRING","medium",weight,f"Indicator present: {needle.decode(errors='replace')}"))
        for rx,weight,detail in SCRIPT_PATTERNS:
            if rx.search(sample): findings.append(Finding("SCRIPT_BEHAVIOR","high" if weight>=18 else "medium",weight,detail))
        if st.st_mode & 0o111: findings.append(Finding("EXECUTABLE_PERMISSION","info",3,"Executable permission bit is set"))
        score=min(100,sum(x.score for x in findings))
        verdict="HIGH_RISK" if score>=45 else "SUSPICIOUS" if score>=20 else "REVIEW" if score>=8 else "NO_STATIC_INDICATORS"
        if typ in ("ELF executable","PE/Windows executable") and verdict=="NO_STATIC_INDICATORS": verdict="REVIEW"
        return Analysis(str(p),file_hash,st.st_size,typ,round(ent,3),score,verdict,findings,[])
    except OSError as e:
        return Analysis(str(p),"",0,"unreadable",0,0,"ERROR",[],[str(e)])
