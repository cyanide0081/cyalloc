#ifndef _TEST_UTILS_H
#define _TEST_UTILS_H

#define KB 1024.0

#define VT_BOLD "\x1B[1m"
#define VT_RESET "\x1B[0m"
#define VT_FG_GREEN "\x1B[92m"
#define VT_FG_RED "\x1B[91m"

#define SP "[" VT_FG_GREEN "🗸" VT_RESET "] "
#define EP "[" VT_FG_RED "🗙" VT_RESET "] "

#define print_s(...) printf(SP "Success: " __VA_ARGS__); putchar('\n')
#define print_e(...) printf(EP "Failure: " __VA_ARGS__); putchar('\n')

#endif /* _TEST_UTILS_H */
