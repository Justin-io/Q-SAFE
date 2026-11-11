"""Reversible quarantine with atomic moves and integrity-checked restore."""
from __future__ import annotations
import hashlib, json, os, time, uuid
from pathlib import Path

def sha256_file(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""): h.update(block)
    return h.hexdigest()

def quarantine(path: str, quarantine_dir: str) -> dict:
    raw=Path(path).expanduser()
    try: raw_stat=raw.lstat()
    except FileNotFoundError: raise
    if raw.is_symlink() or not raw.is_file(): raise ValueError("Only regular non-symlink files can be quarantined")
    src=raw.resolve(strict=True)
    root_raw=Path(quarantine_dir).expanduser()
    if root_raw.is_symlink(): raise ValueError("Quarantine directory must not be a symlink")
    root=root_raw.resolve()
    root.mkdir(parents=True,exist_ok=True,mode=0o700); os.chmod(root,0o700)
    digest=sha256_file(src); token=f"{int(time.time())}-{uuid.uuid4().hex[:10]}"
    dest=root/f"{token}.qsf"; meta=root/f"{token}.json"
    record={"id":token,"original_path":str(src),"quarantine_path":str(dest),"sha256":digest,
            "size":src.stat().st_size,"original_mode":raw_stat.st_mode & 0o777,"quarantined_at":time.time()}
    if src.stat().st_dev!=root.stat().st_dev: raise OSError("Quarantine must be on same filesystem for atomic move")
    os.replace(src,dest); os.chmod(dest,0o600)
    tmp=meta.with_suffix(".json.tmp"); tmp.write_text(json.dumps(record,indent=2)); os.chmod(tmp,0o600); os.replace(tmp,meta)
    return record

def restore(metadata_path: str) -> dict:
    meta_raw=Path(metadata_path).expanduser()
    if meta_raw.is_symlink(): raise ValueError("Metadata path must not be a symlink")
    meta=meta_raw.resolve(strict=True); record=json.loads(meta.read_text())
    src=Path(record["quarantine_path"]); dest=Path(record["original_path"])
    if src.is_symlink() or not src.is_file(): raise FileNotFoundError(src)
    if dest.exists() or dest.is_symlink(): raise FileExistsError(f"Refusing to overwrite existing path: {dest}")
    if sha256_file(src)!=record["sha256"]: raise ValueError("Quarantined content hash mismatch; restore refused")
    dest.parent.mkdir(parents=True,exist_ok=True)
    if src.stat().st_dev!=dest.parent.stat().st_dev: raise OSError("Restore destination must be on same filesystem")
    os.replace(src,dest); os.chmod(dest,int(record.get("original_mode",0o600))); meta.unlink()
    return {"restored_path":str(dest),"sha256":record["sha256"]}
