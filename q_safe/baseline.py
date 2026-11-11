"""Local file identity baselines for detecting unexpected replacement or mutation."""
from __future__ import annotations
import hashlib, json, os, time
from pathlib import Path

def digest(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
    return h.hexdigest()

def build(paths: list[str]) -> dict:
    entries={}
    for raw in paths:
        p=Path(raw).expanduser()
        candidates=[p] if p.is_file() and not p.is_symlink() else (
            Path(base)/name for base,dirs,names in os.walk(p,followlinks=False) for name in names
        ) if p.is_dir() else []
        for f in candidates:
            try:
                if f.is_symlink() or not f.is_file(): continue
                st=f.stat()
                entries[str(f.resolve())]={"sha256":digest(f),"size":st.st_size,"mtime_ns":st.st_mtime_ns,"mode":st.st_mode & 0o777}
            except OSError: continue
    return {"schema":1,"created_at":time.time(),"files":entries}

def compare(baseline_path: str, paths: list[str] | None = None) -> list[dict]:
    data=json.loads(Path(baseline_path).read_text())
    known=data.get("files",{}); current=build(paths or [str(Path(k).parent) for k in known]).get("files",{})
    changes=[]
    for path,entry in current.items():
        old=known.get(path)
        if old is None: changes.append({"path":path,"change":"NEW_FILE","current":entry})
        elif old["sha256"]!=entry["sha256"]: changes.append({"path":path,"change":"CONTENT_CHANGED","previous_sha256":old["sha256"],"current_sha256":entry["sha256"]})
        elif old.get("mode")!=entry.get("mode"): changes.append({"path":path,"change":"MODE_CHANGED","previous_mode":old.get("mode"),"current_mode":entry.get("mode")})
    for path,entry in known.items():
        if path not in current: changes.append({"path":path,"change":"MISSING_FILE","previous_sha256":entry["sha256"]})
    return changes

def save(path: str, paths: list[str]) -> dict:
    data=build(paths); out=Path(path); out.parent.mkdir(parents=True,exist_ok=True)
    tmp=out.with_suffix(out.suffix+".tmp"); tmp.write_text(json.dumps(data,indent=2)); os.chmod(tmp,0o600); os.replace(tmp,out)
    return {"baseline":str(out),"files":len(data["files"]),"created_at":data["created_at"]}
