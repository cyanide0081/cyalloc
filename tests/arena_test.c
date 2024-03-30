#include <cyalloc.h>
#include <stdlib.h>
#include <errno.h>

int main(void) {
    printf("Testing Arena Allocator...\n");

    FILE *f = fopen("tests/sample.txt", "r");
    if (f == NULL) {
        fprintf(stderr, "ERROR: unable to open file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    fseek(f, 0, SEEK_END);
    size_t txt_len = ftell(f);
    rewind(f);

    Arena *arena = arena_init_set_context(txt_len + 1, NULL, NULL);
    char *txt_buf = arena_alloc(txt_len + 1);
    fread(txt_buf, sizeof(char), txt_len, f);

    printf("Successfully allocated message (%zuB)\n", txt_len + 1);

    size_t val = 69;
    memset(arena->buf, val, arena->size);
    printf("Successfully wrote [%zu] to arena (%zuB)\n", val, arena->size);

    arena = arena_deinit();
    return 0;
}
