#include <cyalloc.h>
#include <stdlib.h>
#include <errno.h>
#include "testutils.h"

int main(void) {
    printf("%sTesting Stack Allocator...%s\n", VT_BOLD, VT_RESET);

    FILE *f = fopen("tests/sample.txt", "r");
    if (f == NULL) {
        print_e("unable to open file: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    fseek(f, 0, SEEK_END);
    size_t txt_len = ftell(f);
    rewind(f);

    Stack *s = stack_init(txt_len + 1, NULL, NULL);
    print_s("initialized stack");

    size_t txt_size = txt_len + 1;
    char *txt_buf = stack_alloc(s, txt_size);
    fread(txt_buf, sizeof(char), txt_len, f);
    fclose(f);
    print_s("allocated buffer storing file contents (%.2lfKB)",
        (txt_len + 1) / KB);

    size_t expanded_size = txt_size * 2;
    {
        txt_buf = stack_realloc(s, txt_buf, txt_size, expanded_size);
        if (txt_buf == NULL) {
            print_e("unable to expand buffer in stack");
            exit(EXIT_FAILURE);
        }

        print_s("expanded message buffer (%.2lfKB)", expanded_size / KB);
    }
    {
        StackNode *cur_node = s->state->first_node;
        while (cur_node->next != NULL) cur_node = cur_node->next;
        while (cur_node->offset < cur_node->size) (void)stack_alloc(s, 0x100);

        print_s("exhausted stack (ofs: %zu, size: %zu)",
            cur_node->offset, cur_node->size);
    }
    {
        size_t shrunk_size = expanded_size / 4;
        txt_buf = stack_realloc(s, txt_buf, expanded_size, shrunk_size);
        if (txt_buf == NULL) {
            print_e("unable to shrink buffer in stack");
            exit(EXIT_FAILURE);
        }

        print_s("shrunk message buffer (%.2lfKB)", shrunk_size / KB);
    }
    
#if 0 // figure out some error propagation strategy for the library
    {
        void *dummy = stack_alloc(s, 0x100);
        stack_free(s, txt_buf);
    }
#endif
    
    {
        size_t val = 69;
        StackNode *first_node = s->state->first_node;
        memset(first_node->buf, val, first_node->size);
        print_s("wrote [%zu] to stack (%.2lfKB)", val, first_node->size / KB);
    }

#if 0 // stack_alloc_string not implemented
    {
        const char *str = "basolutely.";
        size_t str_len = strlen(str);
        char *str_buf = stack_alloc_string(s, str, str_len);
        print_s("allocated string into arena (str_buf: '%.*s')",
            (int)str_len, str_buf);
    }
#endif

    stack_deinit(s);
    print_s("deinitialized stack");

    return 0;
}
