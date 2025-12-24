#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

// --- Q-SAFE INSTRUMENTATION ---
extern void qsafe_init(uint64_t* list, uint64_t size);
extern void qsafe_hook(uint64_t target_id);

// Function IDs for Context Hashing
#define ID_MAIN       0x1111
#define ID_PROCESS    0x2222
#define ID_ADMIN      0x9999   // The "Forbidden" function (if reached via overflow)

// Global Allowlist (In a real scenario, this is loaded securely)
uint64_t* allowlist = NULL;
uint64_t allowlist_count = 0;

void load_allowlist() {
    FILE* f = fopen("allowlist.bin", "rb");
    if (!f) {
        printf("[-] Q-SAFE ERROR: allowlist.bin not found. Run neural_oracle.py first!\n");
         // For demo purposes, we might run without it but it will fail all checks.
        exit(1);
    }
    fread(&allowlist_count, sizeof(uint64_t), 1, f);
    allowlist = (uint64_t*)malloc(allowlist_count * sizeof(uint64_t));
    fread(allowlist, sizeof(uint64_t), allowlist_count, f);
    fclose(f);
}

// --- VULNERABLE APPLICATION LOGIC ---

void privileged_admin_panel() {
    // [HOOK] Entry point of the Critical Function
    // If the attacker jumps here directly from 'process_input', 
    // the Previous Context will be 'ID_PROCESS'.
    // The Oracle KNOWS valid flow is ONLY ID_MAIN -> ID_ADMIN (Hypothetically, or maybe it's unreachable)
    // Actually, in this app, this function is NOT CALLED by main. It is "Dead Code" or "Admin Only".
    // So ANY jump here from 'process_input' is ILLEGAL.
    
    qsafe_hook(ID_ADMIN); 
    
    printf("\n[!!!] CRITICAL FAILURE: Admin Panel Accessed! Exploit Successful. [!!!]\n");
    printf("      (If you see this, Q-SAFE failed to stop the ROP)\n");
    exit(0);
}

void process_input(char* filename) {
    // [HOOK] Entry point
    qsafe_hook(ID_PROCESS);

    char buffer[64]; // Small buffer
    FILE* f = fopen(filename, "rb");
    
    if (!f) {
        printf("[-] Failed to open input file: %s\n", filename);
        return;
    }

    printf("[*] Processing file: %s ...\n", filename);
    
    // VULNERABILITY: read until EOF into fixed buffer
    // This allows overwriting the return address on the stack.
    // We use fread with a large size to allow overflow.
    fread(buffer, 1, 512, f); 
    
    printf("    Read Data: %s\n", buffer);
    fclose(f);
    
    // Function returns normally... unless Ret Addr is smashed.
}

int main(int argc, char* argv[]) {
    // 1. Initialize Q-SAFE Protection Layer
    load_allowlist();
    qsafe_init(allowlist, allowlist_count);
    
    // [HOOK] Program Start
    qsafe_hook(ID_MAIN);

    if (argc < 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        printf("Addresses for Exploit Gen:\n");
        printf("  process_input: %p\n", process_input);
        printf("  privileged_admin_panel: %p\n", privileged_admin_panel);
        return 1;
    }

    // 2. Run Application Logic
    process_input(argv[1]);

    printf("[+] Application Terminated Normally.\n");
    return 0;
}
