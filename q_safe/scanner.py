"""Safe filesystem scanner with bounded traversal and exclusions."""
from __future__ import annotations
import json, os
from pathlib import Path
from .analyzer import analyze_file

def scan(roots: list[str], output: str | None = None, max_files: int = 10000, max_bytes: int = 64*1024*1024) -> list[dict]:
    excluded={"/proc","/sys","/dev","/run","/snap"}
    results=[]; seen=0
    for raw in roots:
        root=Path(raw).expanduser()
        if not root.exists() or root.is_symlink(): continue
        candidates=[root] if root.is_file() else (Path(base)/name for base,dirs,names in os.walk(root,followlinks=False) for name in names)
        for p in candidates:
            try:
                rp=p.resolve(strict=True)
                if any(str(rp)==x or str(rp).startswith(x+"/") for x in excluded): continue
                st=p.lstat()
                if not p.is_file() or p.is_symlink() or st.st_size>max_bytes: continue
                seen+=1
                if seen>max_files: break
                results.append(analyze_file(p).to_dict())
            except OSError: continue
        if seen>=max_files: break
    if output:
        out=Path(output); out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text("\n".join(json.dumps(x) for x in results)+"\n")
    return results
