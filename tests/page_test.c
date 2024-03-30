#include <cyalloc.h>
#include <stdlib.h>
#include <errno.h>

int main(void) {
    printf("Testing Page Allocator...\n");

    FILE *f = fopen("tests/sample.txt", "r");
    if (f == NULL) {
        fprintf(stderr, "ERROR: unable to open file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    fseek(f, 0, SEEK_END);
    size_t txt_len = ftell(f);
    rewind(f);

    char *txt_buf = page_alloc(txt_len + 1);
    fread(txt_buf, sizeof(char), txt_len, f);

    printf("Allocated message[%zuB]: '%s' (page size: %zuB)\n",
        txt_len, txt_buf, page_get_size(txt_buf));
    void *new_buf = page_realloc(txt_buf, 0x80);
    if (new_buf == NULL) {
        fprintf(stderr, "ERROR: unable to shrink page size: %s\n",
             strerror(errno));
        exit(EXIT_FAILURE);
    }

    txt_buf = new_buf;

    printf("Successfully shrunk buf size to %zuB\n",
        page_get_size(txt_buf));
    page_free(txt_buf);
    fclose(f);

    return 0;
}
