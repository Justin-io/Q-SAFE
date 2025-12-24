import os
import sys
import json
import subprocess
import re

# Logic:
# 1. Ingest scan_list.txt
# 2. Extract Folders.
# 3. AI STEP 1: Analyze Folders.
# 4. AI STEP 2: Analyze Files in Sus Folders.
# 5. Output suspicious_targets.txt

API_KEY = os.getenv("OPENROUTER_KEY")
MODEL = "google/gemini-2.0-flash-exp:free"

def call_llm(prompt):
    if not API_KEY or API_KEY == "test":
        return None # Trigger Fallback

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": "You are a Cyber Sentinel. Return ONLY items from the list that are suspicious/dangerous. Raw text, one per line."},
            {"role": "user", "content": prompt}
        ]
    }
    
    try:
        # Write payload to temp file to avoid CLI limits
        with open("llm_req.json", "w") as f:
            json.dump(payload, f)
            
        cmd = f'curl -s -X POST https://openrouter.ai/api/v1/chat/completions -H "Authorization: Bearer {API_KEY}" -H "Content-Type: application/json" -d @llm_req.json'
        result = subprocess.check_output(cmd, shell=True)
        data = json.loads(result)
        if "choices" in data:
            return data["choices"][0]["message"]["content"]
    except Exception as e:
        return None
    return None

def main():
    print("[*] AGENT: Initializing Hierarchical Scan...")
    
    try:
        with open("scan_list.txt", "r") as f:
            files = [line.strip() for line in f if line.strip()]
    except:
        return

    # 1. Cluster Folders
    folders = sorted(list(set([os.path.dirname(f) for f in files])))
    # Filter routine folders to save context
    folders = [f for f in folders if not any(x in f for x in ["/proc", "/sys", "/snap", "/var/lib", "/usr/share"])]
    
    print(f"[*] AGENT: Analyzed {len(files)} files into {len(folders)} Context Zones.")
    
    # 2. AI Triage - Folders
    print("[*] AGENT: Querying Neural Ops for High-Risk Zones...")
    sus_folders = []
    
    folder_str = "\n".join(folders[:150]) # Limit for context
    response = call_llm(f"Analyze these folders for user-writable or suspicious locations (e.g. Desktop, tmp, shm):\n{folder_str}")
    
    if response:
        sus_folders = [line.strip() for line in response.split('\n') if line.strip() in folders]
    else:
        # FALLBACK HEURISTICS (Agentic Intuition)
        print("[!] AGENT: Neural Link Unstable. Engaging Local Heuristics.")
        sus_folders = [f for f in folders if "Desktop" in f or "tmp" in f or "Downloads" in f]

    print(f"[*] AGENT: Isolated {len(sus_folders)} High-Risk Zones.")
    
    # 3. AI Triage - Files in Zones
    targets = []
    for folder in sus_folders:
        zone_files = [f for f in files if f.startswith(folder)]
        if not zone_files: continue
        
        print(f"    -> Inspecting Zone: {folder} ({len(zone_files)} objects)")
        
        # In a real deep agent, we would ask LLM again here.
        # "Here are files in /home/justin/Desktop. Which are weird?"
        # For speed/POC, we simply consider ALL files in a SUS folder as targets for DEEP SCAN.
        # This matches "scan only sus folders well".
        targets.extend(zone_files)

    # Write Output
    with open("suspicious_targets.txt", "w") as f:
        for t in targets:
            f.write(t + "\n")
            
    print(f"[*] AGENT: Handoff complete. {len(targets)} vectors queued for Deep Analysis.")

if __name__ == "__main__":
    main()
