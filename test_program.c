#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void memory_leak_example() {
    char *leak = malloc(100);
    strcpy(leak, "This memory will leak");
    printf("Leak created at %p\n", leak);
    // No free() - memory leak!
}

void use_after_free_example() {
    char *ptr = malloc(50);
    strcpy(ptr, "Hello World");
    printf("Before free: %s\n", ptr);
    free(ptr);
    // Use after free - BAD!
    printf("After free: %s\n", ptr);
}

void uninitialized_example() {
    int *arr = malloc(10 * sizeof(int));
    // arr is uninitialized
    printf("Uninitialized value: %d\n", arr[5]);  // Reading uninitialized memory
    free(arr);
}

void invalid_free_example() {
    char *ptr = malloc(100);
    free(ptr);
    free(ptr);  // Double free!
}

int main(int argc, char *argv[]) {
    printf("=== Memory Error Examples ===\n\n");
    
    if (argc > 1) {
        if (strcmp(argv[1], "leak") == 0) {
            printf("Testing memory leak...\n");
            memory_leak_example();
        } else if (strcmp(argv[1], "use-after-free") == 0) {
            printf("Testing use-after-free...\n");
            use_after_free_example();
        } else if (strcmp(argv[1], "uninitialized") == 0) {
            printf("Testing uninitialized memory...\n");
            uninitialized_example();
        } else if (strcmp(argv[1], "double-free") == 0) {
            printf("Testing double free...\n");
            invalid_free_example();
        } else {
            printf("Unknown test: %s\n", argv[1]);
        }
    } else {
        printf("Run with: leak, use-after-free, uninitialized, or double-free\n");
        printf("Example: ./test_program leak\n");
    }
    
    return 0;
}
