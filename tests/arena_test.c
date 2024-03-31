#define CA_LOGGING
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
    size_t txt_size = txt_len + 1;
    char *txt_buf = arena_alloc(txt_size);
    fread(txt_buf, sizeof(char), txt_len, f);

    printf("Successfully allocated message (%zuB)\n", txt_len + 1);

    size_t expanded_size = txt_size * 2;
    txt_buf = arena_realloc(txt_buf, txt_size, expanded_size);
    if (txt_buf == NULL) {
        fprintf(stderr, "ERROR: unable to expand buffer in arena\n");
        exit(EXIT_FAILURE);
    }

    printf("Successfully expanded message buffer (%zuB)\n", expanded_size);

    size_t shrunk_size = expanded_size / 4;
    txt_buf = arena_realloc(txt_buf, expanded_size, shrunk_size);
    if (txt_buf == NULL) {
        fprintf(stderr, "ERROR: unable to shrink buffer in arena\n");
        exit(EXIT_FAILURE);
    }

    printf("Successfully shrunk message buffer (%zuB)\n", shrunk_size);

    size_t val = 69;
    memset(arena->buf, val, arena->size);
    printf("Successfully wrote [%zu] to arena (%zuB)\n", val, arena->size);

    arena = arena_deinit();
    return 0;
}
