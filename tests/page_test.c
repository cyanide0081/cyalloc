#include <cyalloc.h>
#include <stdlib.h>
#include <errno.h>
#include "testutils.h"

int main(void) {
    printf("%sTesting Page Allocator...%s\n", VT_BOLD, VT_RESET);

    FILE *f = fopen("tests/sample.txt", "r");
    if (f == NULL) {
        print_e("unable to open file: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    fseek(f, 0, SEEK_END);
    size_t txt_len = ftell(f);
    rewind(f);

    size_t txt_size = txt_len + 1;
    char *txt_buf = page_alloc(txt_size);
    print_s("allocated page");

    if ((uintptr_t)txt_buf % CA_DEFAULT_ALIGNMENT != 0) {
        print_e("returned memory is not properly aligned");
        exit(EXIT_FAILURE);
    }

    print_s("validated memory alignment");

    fread(txt_buf, sizeof(char), txt_len, f);
    print_s("allocated message (%.2lfKB) (page size: %.2lfKB)",
        txt_len / KB, page_get_size(txt_buf) / KB);

    {
        void *new_buf = page_realloc(txt_buf, 0x80);
        if (new_buf == NULL) {
            print_e("unable to shrink page size: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }

        txt_buf = new_buf;
        txt_size = page_get_size(txt_buf);
        print_s("shrunk page size (%.2lfKB)", txt_size / KB);
    }
    {
        void *new_buf = page_realloc(txt_buf, 0x100000);
        if (new_buf == NULL) {
            print_e("unable to expand page size: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }

        txt_buf = new_buf;
        txt_size = page_get_size(txt_buf);
        print_s("expanded page size (%.2lfkB)",
            page_get_size(txt_buf) / KB);
    }
    {
        size_t val = 69;
        memset(txt_buf, (int)val, txt_size);
        print_s("wrote [%zu] to page (%.2lfKB)", val, txt_size / KB);
    }

    page_free(txt_buf);
    print_s("deallocated page");
    fclose(f);

    return 0;
}
