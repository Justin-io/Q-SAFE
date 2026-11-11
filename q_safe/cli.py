from __future__ import annotations
import argparse, json, sys
from .analyzer import analyze_file
from .scanner import scan
from .quarantine import quarantine, restore

def main() -> int:
    ap=argparse.ArgumentParser(prog="qsafe",description="Defensive file scanner; never executes inspected files")
    sub=ap.add_subparsers(dest="cmd",required=True)
    a=sub.add_parser("scan"); a.add_argument("paths",nargs="+"); a.add_argument("--json",dest="out"); a.add_argument("--max-files",type=int,default=10000)
    f=sub.add_parser("analyze"); f.add_argument("path")
    q=sub.add_parser("quarantine"); q.add_argument("path"); q.add_argument("--dir",default=".qsafe-quarantine"); q.add_argument("--yes",action="store_true")
    r=sub.add_parser("restore"); r.add_argument("metadata")
    args=ap.parse_args()
    if args.cmd=="analyze":
        data=analyze_file(args.path).to_dict(); print(json.dumps(data,indent=2)); return 0 if data["verdict"]!="ERROR" else 2
    if args.cmd=="scan":
        results=scan(args.paths,args.out,args.max_files)
        for x in results: print(f'{x["verdict"]:22} score={x["score"]:3} {x["path"]}')
        print(f"\nScanned {len(results)} files; report: {args.out or 'not saved'}"); return 0
    if args.cmd=="quarantine":
        if not args.yes: print("Refusing: review scan evidence and pass --yes.",file=sys.stderr); return 2
        print(json.dumps(quarantine(args.path,args.dir),indent=2)); return 0
    if args.cmd=="restore": print(json.dumps(restore(args.metadata),indent=2)); return 0
    return 2
if __name__=="__main__": raise SystemExit(main())
