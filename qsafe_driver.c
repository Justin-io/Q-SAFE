#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Mock Function IDs (Must match Neural Oracle)
#define FUNC_MAIN 0x1000
#define FUNC_INIT 0x2000
#define FUNC_A    0x3000
#define FUNC_B    0x4000
#define FUNC_VIOLATION 0xDEAD

// External Assembly Functions
extern void qsafe_init(uint64_t* list, uint64_t size);
extern void qsafe_hook(uint64_t target_id);

// Global Allowlist Buffer
uint64_t* allowlist = NULL;
uint64_t allowlist_count = 0;

void load_allowlist() {
    FILE* f = fopen("allowlist.bin", "rb");
    if (!f) {
        perror("[-] Failed to open allowlist.bin");
        exit(1);
    }
    
    // Read count
    fread(&allowlist_count, sizeof(uint64_t), 1, f);
    
    // Allocate memory
    allowlist = (uint64_t*)malloc(allowlist_count * sizeof(uint64_t));
    
    // Read hashes
    fread(allowlist, sizeof(uint64_t), allowlist_count, f);
    fclose(f);
    
    printf("[+] Loaded %lu valid context hashes.\n", allowlist_count);
}

// ---------------------------------------------------------
// Target Functions to Protect
// ---------------------------------------------------------

void target_function_B() {
    qsafe_hook(FUNC_B); // CONTEXT UPDATE
    printf("    [EXEC] Inside Target Function B (Safe)\n");
}

void target_function_A() {
    qsafe_hook(FUNC_A); // CONTEXT UPDATE
    printf("    [EXEC] Inside Target Function A (Safe)\n");
    target_function_B();
}

void init_system() {
    qsafe_hook(FUNC_INIT); // CONTEXT UPDATE
    printf("    [EXEC] System Initialization\n");
    target_function_A();
}

// ---------------------------------------------------------
// Attack Simulation
// ---------------------------------------------------------

void rop_attack_simulation() {
    printf("\n[!] SIMULATING ROP ATTACK: Jumping to Function B out of order...\n");
    // Normal flow is Init -> A -> B.
    // We are skipping A and jumping straight to B.
    // This should change the rolling hash to an invalid value.
    
    // Note: We don't call qsafe_hook(FUNC_A) here, so the context is missing A.
    // However, Function B calls qsafe_hook(FUNC_B).
    // The previous context was FUNC_INIT (or MAIN -> INIT).
    // The Oracle expects: Hash(Main, Init, A, B)
    // The Code generates: Hash(Main, Init, B) -> UNKNOWN
    
    // Resetting to a state where we just came from Init for the demo
    qsafe_hook(FUNC_INIT); 
    
    printf("    [ATTACK] Hijacking control flow...\n");
    target_function_B();
}

int main(int argc, char* argv[]) {
    printf("=== Q-SAFE Runtime Enforcement POC ===\n");
    
    load_allowlist();
    
    // Initialize Monitor
    qsafe_init(allowlist, allowlist_count);
    
    // Initial Hook for Main
    qsafe_hook(FUNC_MAIN);
    
    if (argc > 1 && strcmp(argv[1], "attack") == 0) {
        rop_attack_simulation();
    } else {
        printf("[*] Running Normal Execution Flow...\n");
        init_system();
        printf("[+] Execution Completed Successfully.\n");
    }
    
    return 0;
}
