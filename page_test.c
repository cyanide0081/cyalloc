#include "cyalloc.h"

int main(void) {
    const char *msg = "Lorem ipsum dolor sit amet, consectetur adipiscing elit,"
        " sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
        " Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris"
        " nisi ut aliquip ex ea commodo consequat.";
    size_t msg_len = strlen(msg);

    void *page = page_alloc(0x100);
    assert(msg_len < 0x100);
    char *buf = memcpy(page, msg, strlen(msg));

    printf("Allocated message[%luB]: '%s'\n", strlen(buf), buf);
    void *new_page = page_realloc(page, 0x80);
    if (new_page == NULL) exit(EXIT_FAILURE);

    page = new_page;
    printf("Allocated page[%luB]: '%s'\n", page_get_size(page), buf);

    page_free(page);
    return 0;
}
