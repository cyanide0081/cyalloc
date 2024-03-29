#include <cyalloc.h>

int main(void) {
    const char *msg = "Hello, World!";

    Arena *arena = arena_init_set_context(0x2000, NULL, NULL);
    char *buf = arena_alloc_c_string(msg);

    printf("Allocated message[%zuB]: '%s'\n", strlen(buf), buf);

    memset(buf, 69, arena->size);
    printf("Arena write successful! (%zuB)\n", arena->size);

    arena = arena_deinit();
    return 0;
}
