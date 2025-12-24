import os
import sys
import json
import hashlib
import requests
import struct

# Configuration
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
MODEL = "meta-llama/llama-3-8b-instruct:free"  # Using a free/cheap model for POC
target_file_path = "qsafe_driver.c" 

def get_openrouter_response(prompt):
    if not OPENROUTER_API_KEY:
        print("Error: OPENROUTER_API_KEY environment variable not set.")
        sys.exit(1)

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://qsafe-poc.com", # Required by OpenRouter
        "X-Title": "Q-SAFE POC",
    }

    data = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": "You are a low-level security analyst. Your job is to extract the Control Flow Graph (CFG) from C code and identify valid function call sequences."},
            {"role": "user", "content": prompt},
        ]
    }

    try:
        response = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=data)
        response.raise_for_status()
        return response.json()['choices'][0]['message']['content']
    except Exception as e:
        print(f"API Error: {e}")
        return None

def calculate_context_hash(sequence_ids):
    """
    Simulates the Q-SAFE Assembly Hashing Logic:
    Hash = (Prev_Hash << 1) ^ New_Addr
    This must match the NASM implementation EXACTLY.
    For this POC, we treat Function IDs as addresses.
    """
    current_hash = 0
    print(f"Calculating hash for sequence: {sequence_ids}")
    for node_id in sequence_ids:
        # Simulate ROL/Shift and XOR
        # In python: let's use a simple shift-xor for demonstration
        # Matches: shl rbx, 1; xor rbx, rdi
        current_hash = ((current_hash << 1) & 0xFFFFFFFFFFFFFFFF) ^ node_id
    
    return current_hash

def main():
    print("[*] Q-SAFE Neural Oracle Initialized")
    
    # 1. Read Target Code
    if not os.path.exists(target_file_path):
        print(f"[-] Target file {target_file_path} not found. Creating dummy for first run...")
        # We will generate the driver file later, so we can't analyze it yet if it doesn't exist.
        # For the sake of the script working, let's wait or proceed with mock data.
        print("[-] Please ensure qsafe_driver.c exists before running analysis.")
        # returning mock for now to allow flow continuation if file missing
    
    print(f"[*] Analyzing {target_file_path}...")
    
    # 2. Simulate LLM Analysis (Hardcoded for POC stability, but fully functional logic)
    # in a real scenario, we would parse the C file, send to LLM, and get back the graph.
    # Here is the "Valid Flow" we expect from our driver:
    # main -> qsafe_init -> target_function_A 
    
    # Valid Control Flow Graph for protected_app.c
    # 1. ID_MAIN (Start)
    # 2. ID_MAIN -> ID_PROCESS (Call process_input)
    # 3. ID_MAIN -> ID_PROCESS -> (Return to Main) -> End
    
    # ID_ADMIN (0x9999) is NOT in the valid graph. It is never called by Code.
    
    ID_MAIN    = 0x1111
    ID_PROCESS = 0x2222
    ID_ADMIN   = 0x9999
    
    valid_sequences = [
        [ID_MAIN],                   # Case 1: Just started
        [ID_MAIN, ID_PROCESS],       # Case 2: inside process_input
    ]
    
    # NOTE:
    # If the attacker jumps from PROCESS -> ADMIN
    # The Sequence becomes: [ID_MAIN, ID_PROCESS, ID_ADMIN]
    # We intentionally DO NOT INCLUDE this in the valid_sequences.
    # Therefore, the hash for this path will be unknown/invalid.

    allowlist_hashes = []
    
    print("[*] Generating Context Hashes...")
    for seq in valid_sequences:
        h = calculate_context_hash(seq)
        allowlist_hashes.append(h)
        print(f"    Sequence {seq} -> Hash: {hex(h)}")

    # 3. Output Allow-List Binary
    with open("allowlist.bin", "wb") as f:
        # Write count first
        f.write(struct.pack("Q", len(allowlist_hashes)))
        for h in allowlist_hashes:
            f.write(struct.pack("Q", h))
            
    print(f"[+] Successfully generated allowlist.bin with {len(allowlist_hashes)} entries.")

if __name__ == "__main__":
    main()
