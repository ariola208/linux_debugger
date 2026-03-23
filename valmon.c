#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <signal.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <pthread.h>

//=============================================================================
// Memory Shadow State (like Valgrind's V-bits)
//=============================================================================
typedef enum {
    MEM_DEFINED = 0,      // Valid initialized memory
    MEM_UNDEFINED = 1,    // Uninitialized memory
    MEM_NOACCESS = 2,     // Invalid/unaddressable memory
    MEM_FREED = 3         // Freed memory (use-after-free)
} MemState;

typedef struct ShadowBlock {
    void* addr;
    size_t size;
    MemState state;
    struct ShadowBlock* next;
    struct ShadowBlock* prev;
    bool is_heap;
    unsigned long alloc_stack[16];  // Stack trace on allocation
    int alloc_depth;
    unsigned long free_stack[16];    // Stack trace on free
    int free_depth;
} ShadowBlock;

typedef struct {
    ShadowBlock* blocks;
    pthread_rwlock_t lock;
    size_t total_allocations;
    size_t total_frees;
    size_t errors_found;
    size_t bytes_allocated;
    size_t bytes_freed;
} ShadowMemory;

//=============================================================================
// Instrumentation Context (like Valgrind's core)
//=============================================================================
typedef struct {
    pid_t traced_pid;
    bool attached;
    bool verbose;
    bool track_origins;      // Track uninitialized value origins
    bool show_leaks;
    bool fatal_errors;
    ShadowMemory shadow;
    
    // JIT/Instrumentation cache
    void* instrumented_code_cache;
    size_t cache_size;
    
    // Call stack tracking
    unsigned long call_stack[256];
    int call_stack_depth;
    
    // Suppression rules
    char** suppressions;
    int suppression_count;
    
    // Statistics
    struct {
        size_t insns_executed;
        size_t loads_executed;
        size_t stores_executed;
        size_t syscalls_trapped;
        size_t errors_reported;
    } stats;
} ValgrindCore;

ValgrindCore vg = {0};

//=============================================================================
// Shadow Memory Management
//=============================================================================

void init_shadow_memory() {
    pthread_rwlock_init(&vg.shadow.lock, NULL);
    vg.shadow.blocks = NULL;
    vg.shadow.total_allocations = 0;
    vg.shadow.total_frees = 0;
    vg.shadow.errors_found = 0;
    vg.shadow.bytes_allocated = 0;
    vg.shadow.bytes_freed = 0;
}

void add_shadow_block(void* addr, size_t size, MemState state, bool is_heap) {
    ShadowBlock* block = malloc(sizeof(ShadowBlock));
    block->addr = addr;
    block->size = size;
    block->state = state;
    block->is_heap = is_heap;
    block->next = vg.shadow.blocks;
    block->prev = NULL;
    block->alloc_depth = vg.call_stack_depth;
    
    // Capture stack trace
    for (int i = 0; i < vg.call_stack_depth && i < 16; i++) {
        block->alloc_stack[i] = vg.call_stack[i];
    }
    block->free_depth = 0;
    
    if (vg.shadow.blocks) {
        vg.shadow.blocks->prev = block;
    }
    vg.shadow.blocks = block;
    
    if (is_heap) {
        vg.shadow.total_allocations++;
        vg.shadow.bytes_allocated += size;
    }
}

ShadowBlock* find_shadow_block(void* addr) {
    ShadowBlock* block = vg.shadow.blocks;
    while (block) {
        if (addr >= block->addr && addr < (block->addr + block->size)) {
            return block;
        }
        block = block->next;
    }
    return NULL;
}

void remove_shadow_block(void* addr) {
    ShadowBlock* block = find_shadow_block(addr);
    if (!block) return;
    
    if (block->prev) block->prev->next = block->next;
    if (block->next) block->next->prev = block->prev;
    if (vg.shadow.blocks == block) vg.shadow.blocks = block->next;
    
    if (block->is_heap) {
        vg.shadow.total_frees++;
        vg.shadow.bytes_freed += block->size;
        
        // Capture stack trace on free
        block->free_depth = vg.call_stack_depth;
        for (int i = 0; i < vg.call_stack_depth && i < 16; i++) {
            block->free_stack[i] = vg.call_stack[i];
        }
        
        // Mark as freed but keep block for use-after-free detection
        block->state = MEM_FREED;
        // Don't free the block yet - keep for error reporting
    } else {
        free(block);
    }
}

//=============================================================================
// Error Reporting (like Valgrind's error manager)
//=============================================================================

typedef enum {
    ERR_INVALID_READ,
    ERR_INVALID_WRITE,
    ERR_USE_UNINITIALIZED,
    ERR_USE_AFTER_FREE,
    ERR_MEMORY_LEAK,
    ERR_DOUBLE_FREE,
    ERR_INVALID_FREE,
    ERR_SYSLOG_PARAM
} ErrorType;

typedef struct {
    ErrorType type;
    void* address;
    size_t size;
    char* description;
    unsigned long stack[32];
    int stack_depth;
    ShadowBlock* related_block;
} Error;

Error errors[1024];
int error_count = 0;

void report_error(ErrorType type, void* addr, size_t size, const char* msg) {
    if (error_count >= 1024) return;
    
    Error* err = &errors[error_count++];
    err->type = type;
    err->address = addr;
    err->size = size;
    err->description = strdup(msg);
    err->stack_depth = vg.call_stack_depth;
    memcpy(err->stack, vg.call_stack, vg.call_stack_depth * sizeof(unsigned long));
    err->related_block = find_shadow_block(addr);
    
    vg.shadow.errors_found++;
    vg.stats.errors_reported++;
    
    // Print immediately if verbose
    if (vg.verbose) {
        printf("\n===========================================================\n");
        printf("==%d== ERROR: %s\n", vg.traced_pid, msg);
        printf("==%d==    Address: %p\n", vg.traced_pid, addr);
        printf("==%d==    Size: %zu bytes\n", vg.traced_pid, size);
        
        if (err->related_block && err->related_block->is_heap) {
            printf("==%d==    Block allocated at:\n", vg.traced_pid);
            for (int i = 0; i < err->related_block->alloc_depth && i < 8; i++) {
                printf("==%d==        [%d] %p\n", vg.traced_pid, i, 
                       (void*)err->related_block->alloc_stack[i]);
            }
            
            if (err->related_block->state == MEM_FREED) {
                printf("==%d==    Block freed at:\n", vg.traced_pid);
                for (int i = 0; i < err->related_block->free_depth && i < 8; i++) {
                    printf("==%d==        [%d] %p\n", vg.traced_pid, i,
                           (void*)err->related_block->free_stack[i]);
                }
            }
        }
        
        printf("==%d==    Current stack:\n", vg.traced_pid);
        for (int i = 0; i < vg.call_stack_depth && i < 16; i++) {
            printf("==%d==        [%d] %p\n", vg.traced_pid, i, (void*)vg.call_stack[i]);
        }
        printf("===========================================================\n");
        
        if (vg.fatal_errors) {
            printf("Fatal error detected, stopping...\n");
            exit(1);
        }
    }
}

//=============================================================================
// Memory Access Instrumentation (like Valgrind's Memcheck)
//=============================================================================

void check_memory_access(void* addr, size_t size, bool is_write) {
    // Check if address is valid
    if (addr == NULL) {
        report_error(is_write ? ERR_INVALID_WRITE : ERR_INVALID_READ,
                    addr, size, is_write ? "Invalid write to NULL" : "Invalid read from NULL");
        return;
    }
    
    ShadowBlock* block = find_shadow_block(addr);
    
    if (!block) {
        // Check if this is stack memory (approximate)
        unsigned long rsp;
        asm volatile("mov %%rsp, %0" : "=r"(rsp));
        
        if ((unsigned long)addr > rsp - 0x100000 && (unsigned long)addr < rsp + 0x100000) {
            // Stack memory - always considered defined
            return;
        }
        
        report_error(is_write ? ERR_INVALID_WRITE : ERR_INVALID_READ,
                    addr, size, is_write ? "Invalid write to unallocated memory" : "Invalid read from unallocated memory");
        return;
    }
    
    if (block->state == MEM_FREED) {
        report_error(is_write ? ERR_INVALID_WRITE : ERR_INVALID_READ,
                    addr, size, is_write ? "Write after free" : "Read after free");
        return;
    }
    
    if (block->state == MEM_UNDEFINED && !is_write) {
        report_error(ERR_USE_UNINITIALIZED, addr, size, "Use of uninitialized value");
    }
    
    if (block->state == MEM_DEFINED) {
        // Valid access
        if (is_write) {
            // Writing marks memory as defined
            block->state = MEM_DEFINED;
        }
    }
}

//=============================================================================
// Function Interception (like Valgrind's wrappers)
//=============================================================================

void* __wrap_malloc(size_t size) {
    void* ptr = __builtin_return_address(0);
    // Actually call malloc
    void* result = malloc(size);
    
    if (result) {
        pthread_rwlock_wrlock(&vg.shadow.lock);
        add_shadow_block(result, size, MEM_UNDEFINED, true);
        pthread_rwlock_unlock(&vg.shadow.lock);
        
        if (vg.verbose) {
            printf("==%d== malloc(%zu) = %p\n", vg.traced_pid, size, result);
        }
    }
    
    return result;
}

void __wrap_free(void* ptr) {
    if (!ptr) return;
    
    pthread_rwlock_wrlock(&vg.shadow.lock);
    ShadowBlock* block = find_shadow_block(ptr);
    
    if (!block) {
        pthread_rwlock_unlock(&vg.shadow.lock);
        report_error(ERR_INVALID_FREE, ptr, 0, "Invalid free (pointer not allocated)");
        return;
    }
    
    if (block->state == MEM_FREED) {
        pthread_rwlock_unlock(&vg.shadow.lock);
        report_error(ERR_DOUBLE_FREE, ptr, 0, "Double free detected");
        return;
    }
    
    remove_shadow_block(ptr);
    free(ptr);
    pthread_rwlock_unlock(&vg.shadow.lock);
}

void* __wrap_calloc(size_t nmemb, size_t size) {
    void* result = calloc(nmemb, size);
    
    if (result) {
        pthread_rwlock_wrlock(&vg.shadow.lock);
        // calloc initializes memory to zero, so it's defined
        add_shadow_block(result, nmemb * size, MEM_DEFINED, true);
        pthread_rwlock_unlock(&vg.shadow.lock);
    }
    
    return result;
}

void* __wrap_realloc(void* ptr, size_t size) {
    if (!ptr) return __wrap_malloc(size);
    if (size == 0) {
        __wrap_free(ptr);
        return NULL;
    }
    
    void* result = realloc(ptr, size);
    
    if (result) {
        pthread_rwlock_wrlock(&vg.shadow.lock);
        remove_shadow_block(ptr);
        add_shadow_block(result, size, MEM_UNDEFINED, true);
        pthread_rwlock_unlock(&vg.shadow.lock);
    }
    
    return result;
}

//=============================================================================
// Syscall Instrumentation (like Valgrind's syscall wrappers)
//=============================================================================

void handle_syscall(struct user_regs_struct* regs) {
    // Intercept syscalls and validate arguments
    long syscall_num = regs->orig_rax;
    
    switch (syscall_num) {
        case 0:  // read
            check_memory_access((void*)regs->rsi, regs->rdx, true);
            break;
        case 1:  // write
            check_memory_access((void*)regs->rsi, regs->rdx, false);
            break;
        case 9:  // mmap
            // Validate mmap parameters
            if (regs->rsi > 0) {
                // Will be tracked when actual mapping happens
            }
            break;
        case 11:  // munmap
            check_memory_access((void*)regs->rdi, regs->rsi, false);
            break;
    }
    
    vg.stats.syscalls_trapped++;
}

//=============================================================================
// Instruction Instrumentation (like Valgrind's IR)
//=============================================================================

void instrument_instruction(struct user_regs_struct* regs, unsigned char* insn, size_t len) {
    vg.stats.insns_executed++;
    
    // Simple instruction decoding (just for demo)
    // Real Valgrind does full instruction translation to IR
    
    if (len >= 1) {
        // Check for MOV instruction patterns (very simplified)
        if ((insn[0] & 0xF0) == 0x80 ||  // MOV to/from memory
            (insn[0] & 0xFC) == 0x88) {   // MOV byte/word/dword
            
            // This is a memory access instruction
            // Extract address from registers (simplified)
            // In reality, you'd need full instruction decoding
            
            // For demonstration, we'll just mark that we saw memory access
            vg.stats.loads_executed++;
            
            // Check if this is a read or write
            bool is_write = (insn[0] & 0x02) != 0;
            
            // Get memory address from register (very simplified)
            // Real implementation would decode MODRM and SIB bytes
            unsigned long addr = regs->rsi;  // Just an example
            
            if (addr) {
                check_memory_access((void*)addr, 8, is_write);
            }
        }
    }
}

//=============================================================================
// Stack Trace Capture
//=============================================================================

void capture_stack_trace() {
    unsigned long rbp;
    asm volatile("mov %%rbp, %0" : "=r"(rbp));
    
    vg.call_stack_depth = 0;
    unsigned long* frame = (unsigned long*)rbp;
    
    for (int i = 0; i < 32 && frame && vg.call_stack_depth < 256; i++) {
        unsigned long ret_addr = frame[1];
        if (ret_addr == 0) break;
        
        vg.call_stack[vg.call_stack_depth++] = ret_addr;
        frame = (unsigned long*)frame[0];
        
        // Stop if we reach main or entry point
        if (ret_addr < 0x1000) break;
    }
}

//=============================================================================
// Memory Leak Detection (like Valgrind's leak checker)
//=============================================================================

void detect_memory_leaks() {
    printf("\n==%d== Memory leak report\n", vg.traced_pid);
    printf("==%d== Total allocations: %zu\n", vg.traced_pid, vg.shadow.total_allocations);
    printf("==%d== Total frees: %zu\n", vg.traced_pid, vg.shadow.total_frees);
    printf("==%d== Bytes allocated: %zu\n", vg.traced_pid, vg.shadow.bytes_allocated);
    printf("==%d== Bytes freed: %zu\n", vg.traced_pid, vg.shadow.bytes_freed);
    printf("==%d== Leaked bytes: %zd\n", vg.traced_pid, 
           (ssize_t)vg.shadow.bytes_allocated - (ssize_t)vg.shadow.bytes_freed);
    
    ShadowBlock* block = vg.shadow.blocks;
    int leak_count = 0;
    
    while (block) {
        if (block->is_heap && block->state != MEM_FREED) {
            leak_count++;
            printf("==%d== Leak %d: %p (%zu bytes)\n", 
                   vg.traced_pid, leak_count, block->addr, block->size);
            
            if (vg.track_origins && block->alloc_depth > 0) {
                printf("==%d==    Allocated at:\n", vg.traced_pid);
                for (int i = 0; i < block->alloc_depth && i < 8; i++) {
                    printf("==%d==        [%d] %p\n", vg.traced_pid, i, 
                           (void*)block->alloc_stack[i]);
                }
            }
        }
        block = block->next;
    }
    
    if (leak_count == 0) {
        printf("==%d== No memory leaks detected\n", vg.traced_pid);
    } else {
        printf("==%d== %d leaks detected\n", vg.traced_pid, leak_count);
    }
}

//=============================================================================
// Core Debugger Loop (like Valgrind's scheduler)
//=============================================================================

void run_instrumented_program(pid_t pid) {
    int status;
    struct user_regs_struct regs;
    unsigned char instruction[16];
    
    vg.traced_pid = pid;
    
    while (1) {
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            break;
        }
        
        if (WIFEXITED(status)) {
            printf("\n==%d== Program exited with status %d\n", pid, WEXITSTATUS(status));
            break;
        }
        
        if (WIFSIGNALED(status)) {
            printf("\n==%d== Program terminated by signal %d\n", pid, WTERMSIG(status));
            break;
        }
        
        if (!WIFSTOPPED(status)) {
            continue;
        }
        
        // Get registers
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
            perror("ptrace GETREGS");
            break;
        }
        
        // Check if it's a syscall
        if (regs.orig_rax != -1) {
            handle_syscall(&regs);
        }
        
        // Read instruction
        for (int i = 0; i < sizeof(instruction); i++) {
            long word = ptrace(PTRACE_PEEKTEXT, pid, regs.rip + i, NULL);
            if (word == -1 && errno) break;
            instruction[i] = word & 0xFF;
        }
        
        // Instrument the instruction
        instrument_instruction(&regs, instruction, sizeof(instruction));
        
        // Capture stack trace
        capture_stack_trace();
        
        // Single step
        if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
            perror("ptrace SINGLESTEP");
            break;
        }
    }
    
    // Final leak check
    if (vg.show_leaks) {
        detect_memory_leaks();
    }
    
    // Print statistics
    printf("\n==%d== Statistics:\n", pid);
    printf("==%d==   Instructions executed: %zu\n", pid, vg.stats.insns_executed);
    printf("==%d==   Memory loads: %zu\n", pid, vg.stats.loads_executed);
    printf("==%d==   Memory stores: %zu\n", pid, vg.stats.stores_executed);
    printf("==%d==   Syscalls trapped: %zu\n", pid, vg.stats.syscalls_trapped);
    printf("==%d==   Errors reported: %zu\n", pid, vg.stats.errors_reported);
}

//=============================================================================
// Initialization and Setup
//=============================================================================

void setup_instrumentation() {
    // Setup function interposition
    // In a real implementation, you'd use LD_PRELOAD or similar
    // This is a simplified version
    
    init_shadow_memory();
    
    // Set default options
    vg.verbose = true;
    vg.track_origins = true;
    vg.show_leaks = true;
    vg.fatal_errors = false;
}

int spawn_instrumented_process(char* program, char** args) {
    pid_t pid = fork();
    
    if (pid == 0) {
        // Child process
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace TRACEME");
            exit(1);
        }
        
        // Raise SIGSTOP to stop for instrumentation
        raise(SIGSTOP);
        
        // Execute program
        execvp(program, args);
        perror("execvp");
        exit(1);
    }
    else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
            printf("==%d== Instrumenting process %d\n", pid, pid);
            return pid;
        }
    }
    else {
        perror("fork");
    }
    
    return -1;
}

//=============================================================================
// Suppressions (like Valgrind's suppression files)
//=============================================================================

void load_suppressions(const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return;
    
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        
        vg.suppressions = realloc(vg.suppressions, 
                                   (vg.suppression_count + 1) * sizeof(char*));
        vg.suppressions[vg.suppression_count++] = strdup(line);
    }
    
    fclose(f);
    printf("Loaded %d suppressions\n", vg.suppression_count);
}

bool is_suppressed(Error* err) {
    for (int i = 0; i < vg.suppression_count; i++) {
        if (strstr(err->description, vg.suppressions[i])) {
            return true;
        }
    }
    return false;
}

//=============================================================================
// Main Entry Point
//=============================================================================

void print_valgrind_banner() {
    printf("============================================================\n");
    printf("== Valgrind-inspired Memory Debugger\n");
    printf("== Copyright (C) 2024\n");
    printf("== Using ptrace-based instrumentation\n");
    printf("============================================================\n");
}

void print_usage(const char* progname) {
    printf("Usage: %s [options] <program> [args...]\n", progname);
    printf("Options:\n");
    printf("  --verbose           Enable verbose output\n");
    printf("  --quiet             Suppress non-error messages\n");
    printf("  --leak-check=full   Show detailed memory leak information\n");
    printf("  --track-origins=yes Track origins of uninitialized values\n");
    printf("  --suppressions=<file> Load suppressions from file\n");
    printf("  --fatal-errors      Stop on first error\n");
    printf("  --help              Show this help\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    print_valgrind_banner();
    setup_instrumentation();
    
    // Parse options
    int prog_index = 1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0) {
            vg.verbose = true;
            prog_index++;
        }
        else if (strcmp(argv[i], "--quiet") == 0) {
            vg.verbose = false;
            prog_index++;
        }
        else if (strcmp(argv[i], "--leak-check=full") == 0) {
            vg.show_leaks = true;
            prog_index++;
        }
        else if (strcmp(argv[i], "--track-origins=yes") == 0) {
            vg.track_origins = true;
            prog_index++;
        }
        else if (strncmp(argv[i], "--suppressions=", 15) == 0) {
            load_suppressions(argv[i] + 15);
            prog_index++;
        }
        else if (strcmp(argv[i], "--fatal-errors") == 0) {
            vg.fatal_errors = true;
            prog_index++;
        }
        else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        else {
            break;
        }
    }
    
    if (prog_index >= argc) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Spawn and instrument process
    pid_t pid = spawn_instrumented_process(argv[prog_index], &argv[prog_index]);
    if (pid == -1) {
        fprintf(stderr, "Failed to spawn process\n");
        return 1;
    }
    
    // Run instrumentation
    run_instrumented_program(pid);
    
    // Cleanup
    if (vg.attached) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
    }
    
    // Free suppressions
    for (int i = 0; i < vg.suppression_count; i++) {
        free(vg.suppressions[i]);
    }
    free(vg.suppressions);
    
    printf("==%d== Instrumentation complete\n", pid);
    
    return 0;
}
