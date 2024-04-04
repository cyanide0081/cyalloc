#ifndef _CYALLOC_H
#define _CYALLOC_H

#include <stdio.h>   // for optional logging
#include <stdint.h>  // uintptr_t and size_t
#include <stdbool.h> // bool
#include <stdarg.h>  // va_args
#include <string.h>  // memcpy and memset
#include <assert.h>  // assertions

#define CA_DEFAULT_ALIGNMENT (2 * sizeof(void*))

static inline bool _ca_is_power_of_two(uintptr_t n) {
    return (n & (n - 1)) == 0;
}

static inline uintptr_t _ca_mem_align_forward(uintptr_t ptr, size_t align) {
    assert(_ca_is_power_of_two(align));

    uintptr_t mod = ptr & (align - 1);
    return mod ? ptr + align - mod : ptr;
}

/* ---------- Page Allocator Section ---------- */
#if defined(_WIN32)
#include <windows.h>
#define CA_PAGE_SIZE (4 * 1024)
#elif defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
#include <unistd.h>
#include <sys/mman.h>

#if defined(__APPLE__) && defined(__aarch64__)
#define CA_PAGE_SIZE (16 * 1024)
#else
#define CA_PAGE_SIZE (4 * 1024)
#endif /* __APPLE__ */
#endif /* _WIN32 */


typedef struct PageChunk {
    size_t size;  // Total size of allocation (including aligned meta-chunk)
    size_t align; // Alignment (for tracking down the start of the allocation)
} PageChunk;

/* Returns the total size of the page(s) reserved by the OS (including chunk) */
static inline size_t _ca_page_aligned_size(void *ptr) {
    PageChunk *chunk = (PageChunk*)((char*)ptr - sizeof(*chunk));
    return chunk->size;
}

static inline void *page_alloc_align(size_t size, size_t align) {
    assert(size > 0);

    uintptr_t chunk_aligned_size =
        _ca_mem_align_forward(sizeof(PageChunk), align);
    uintptr_t aligned_size =
        _ca_mem_align_forward((uintptr_t)size + chunk_aligned_size,
            align > CA_PAGE_SIZE ? align : CA_PAGE_SIZE);
    PageChunk chunk = { .size = aligned_size, .align = align };

    void *mem = NULL;
#ifdef _WIN32
    mem = VirtualAlloc(NULL, aligned_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
    mem = mmap(NULL, aligned_size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANON, -1, 0);
#endif /* _WIN32 */

    if (mem == NULL) return NULL;

    /* Append size of allocation to the area just before the first byte
     * of aligned memory which will be handed to the caller at return */
    memcpy((char*)mem + chunk_aligned_size - sizeof(chunk),
        &chunk, sizeof(chunk));
    return (void*)((char*)mem + chunk_aligned_size);
}

/* Returns an allocated block of memory containing [size] bytes rounded
 * up to a multiple of the system's page size (with default alignment) */
static inline void *page_alloc(size_t size) {
    return page_alloc_align(size, CA_DEFAULT_ALIGNMENT);
}

/* Immediately returns the allocated memory starting @ [ptr] back to the OS */
static inline void page_free(void *ptr) {
#ifdef _WIN32
    VirtualFree(ptr, 0, MEM_RELEASE);
#else
    /* All allocated pages will have a metadata chunk right before the
     * beginning of the pointer that must be stepped back into
     * in order to free the whole block -> [*...[PageChunk][ptr]...] */
    PageChunk *chunk = (PageChunk*)((char*)ptr - sizeof(*chunk));
    const size_t chunk_aligned_size = 
        _ca_mem_align_forward(sizeof(*chunk), chunk->align);

    munmap((char*)ptr - chunk_aligned_size, chunk->size);
#endif
}

static inline void *page_realloc_align(
    void *ptr,
    size_t new_size,
    size_t align
) {
    PageChunk *chunk = (PageChunk*)((char*)ptr - sizeof(*chunk));

    const size_t current_size = chunk->size;
    const size_t new_aligned_size = _ca_mem_align_forward(new_size, align);
    const size_t chunk_aligned_size =
        _ca_mem_align_forward(sizeof(*chunk), chunk->align);
    const size_t new_page_aligned_size = _ca_mem_align_forward(
        new_aligned_size + chunk_aligned_size, CA_PAGE_SIZE);

    /* TODO: free excess pages if possible
     * (free memory) starting at
     * (current_size - new_aligned_size + chunk_aligned_size) */
    if (new_page_aligned_size <= current_size) {
        size_t chunk_to_free = current_size - new_size - chunk_aligned_size;

#ifdef _WIN32
        VirtualFree((char*)ptr + new_size, chunk_to_free, MEM_RELEASE);
#else
        munmap((char*)ptr + new_size, chunk_to_free);
#endif

        chunk->size = new_page_aligned_size;
        return ptr;
    }

    void *new_ptr = page_alloc(new_aligned_size);
    if (new_ptr == NULL) return NULL;

    memcpy(new_ptr, ptr, current_size - chunk_aligned_size);
    page_free(ptr);

    return new_ptr;
}

/* Returns a pointer to a block of memory containing the same data as [ptr]
 * (or up to where the new size allows, in case it's smaller the current size)
 * If a reallocation is needed and FAILS, page_realloc() returns NULL and
 * DOESN'T free the block pointed to by [ptr] */
static inline void *page_realloc(void *ptr, size_t new_size) {
    return page_realloc_align(ptr, new_size, CA_DEFAULT_ALIGNMENT);
}

/* Returns the allocation size that was given to page_alloc/page_realloc */
static inline size_t page_get_size(void *ptr) {
    PageChunk *chunk = (PageChunk*)((char*)ptr - sizeof(*chunk));
    return chunk->size - _ca_mem_align_forward(sizeof(*chunk), chunk->align);
}

/* ---------- Arena Allocator Section ---------- */
typedef struct ArenaNode {
    unsigned char *buf;     // actual arena memory
    size_t size;            // size of the buffer in bytes
    size_t offset;          // offset to first byte of (unaligned) free memory
    size_t prev_offset;     // offset to first byte of previous allocation
    struct ArenaNode *next; // next node (duh)
} ArenaNode;

typedef struct ArenaState {
    ArenaNode *first_node;
    size_t end_index;       // not yet sure what this'll be used for
} ArenaState;

typedef struct Arena {
    void *(*alloc)(size_t); // backing allocator
    void (*free)(void*);    // backing deallocator
    ArenaState *state;
} Arena;

/* TODO: 
 *  1. move the arena configuration state into a new ArenaState struct which
 *     will also store the linked list of buffers allocated using the backing
 *     allocator
 */

/* Default initial size set to one page */
#define CA_ARENA_INIT_SIZE     CA_PAGE_SIZE
#define CA_ARENA_GROWTH_FACTOR 2.0

/* Returns an initialized Arena struct with a capacity of initial_size
 * takes in a backing allocator and deallocator complying to the standard
 * malloc() interface (uses malloc() and free() in case they're null) */
static inline Arena *arena_init(
    size_t initial_size,
    void *(*backing_allocator)(size_t),
    void (*backing_deallocator)(void*)
) {
    if (initial_size == 0) initial_size = CA_ARENA_INIT_SIZE;

    if (backing_allocator == NULL && backing_deallocator == NULL) {
        backing_allocator = page_alloc;
        backing_deallocator = page_free; 
    } else if (backing_allocator == NULL || backing_deallocator == NULL) {
        return NULL;
    }

    size_t size = sizeof(Arena) + sizeof(ArenaState) +
        sizeof(ArenaNode) + initial_size;
    Arena *arena = backing_allocator(size);
    if (arena == NULL) return NULL;

    arena->alloc = backing_allocator;
    arena->free = backing_deallocator;
    arena->state = (ArenaState*)(arena + 1);

    arena->state->first_node = (ArenaNode*)(arena->state + 1);

    ArenaNode *first_node = arena->state->first_node;
    first_node->buf = (unsigned char*)(arena->state->first_node + 1); 
    first_node->size = initial_size;

    return arena;
}

static inline ArenaNode *_ca_arena_create_node(Arena *arena, size_t size) {
    ArenaNode *cur_node = arena->state->first_node;
    while (cur_node != NULL) cur_node = cur_node->next;

    size_t cur_node_size = sizeof(ArenaNode) + size;
    cur_node = arena->alloc(cur_node_size);
    if (cur_node == NULL) return NULL;

    cur_node->buf = (unsigned char*)(arena->state->first_node + 1);
    cur_node->size = size;

    return cur_node;
}

static inline void *arena_alloc_align(
    Arena *arena,
    size_t bytes,
    size_t align
) {
    ArenaNode *cur_node = arena->state->first_node;
    uintptr_t buf = (uintptr_t)cur_node->buf, curr_ptr = buf + cur_node->offset;
    uintptr_t offset = _ca_mem_align_forward(curr_ptr, align) - buf;
    while (offset + bytes > cur_node->size) {
        /* need more memory! (add new node to linked list) */
        if (cur_node->next == NULL) {
            size_t new_size = (size_t)(cur_node->size * CA_ARENA_GROWTH_FACTOR);
            if (bytes + sizeof(ArenaNode) > new_size + sizeof(ArenaNode)) {
                new_size = _ca_mem_align_forward(bytes, CA_PAGE_SIZE);
            }

            cur_node->next = _ca_arena_create_node(arena, new_size);
        }

        cur_node = cur_node->next;

        buf = (uintptr_t)cur_node->buf;
        curr_ptr = buf + cur_node->offset;
        offset = _ca_mem_align_forward(curr_ptr, align) - buf;
    }

    cur_node->prev_offset = offset;
    cur_node->offset = offset + bytes;

    return (void*)(cur_node->buf + offset);
}

/* Returns a suitable place in memory for a buffer of the given size in bytes,
 * from somewhere within the current context arena */
static inline void *arena_alloc(Arena *arena, size_t bytes) {
    return arena_alloc_align(arena, bytes, CA_DEFAULT_ALIGNMENT);
}

/* Frees all memory allocated for the current arena including itself
 * (and any other memory necessary for internal keeping) */
static inline void arena_deinit(Arena *arena) {
    ArenaNode *cur_node = arena->state->first_node, *next = cur_node->next;
    while (next != NULL) {
        cur_node = next;
        next = next->next;
        arena->free(cur_node); 
    }

    arena->free(arena);
}

/* Resizes the last allocation done in the arena (if [old_memory] doesn't match
 * the return value of the last allocation done in [arena], this function
 * returns NULL) */
static inline void *arena_realloc_align(
    Arena *arena,
    void *old_memory,
    size_t old_size,
    size_t new_size,
    size_t align
) {
    assert(_ca_is_power_of_two(align));

    unsigned char *old_mem = old_memory;
    if (old_mem == NULL || old_size == 0) {
        return arena_alloc_align(arena, new_size, align);
    }

    ArenaNode *cur_node = arena->state->first_node;
    while (cur_node->next != NULL) cur_node = cur_node->next;

    if (cur_node->buf + cur_node->prev_offset != old_mem) return NULL;

    size_t aligned_size = _ca_mem_align_forward(new_size, align);
    uintptr_t aligned_offset = _ca_mem_align_forward(cur_node->offset, align);
    unsigned char *new_mem = old_mem + aligned_offset;
    if (new_mem + aligned_size < cur_node->buf + cur_node->size) {
        cur_node->offset = aligned_offset + aligned_size; 
        if (cur_node->offset < cur_node->prev_offset + old_size) {
            memset(cur_node->buf + cur_node->offset, 0,
                old_size - aligned_size);
        }

        return (void*)new_mem;
    }

    void *new_memory = arena_alloc_align(arena, new_size, align);
    if (new_memory == NULL) return NULL;
    
    size_t copy_size = old_size < new_size ? old_size : new_size;
    memmove(new_memory, old_memory, copy_size);
    return new_memory;
}

static inline void *arena_realloc(
    Arena *arena,
    void *old_memory,
    size_t old_size,
    size_t new_size
) {
    return arena_realloc_align(arena, old_memory,
        old_size, new_size, CA_DEFAULT_ALIGNMENT);
}

/* Frees all the excess allocations done by the current context arena and
 * clears all of its space to zero */
static inline void arena_flush(Arena *arena) {
    ArenaNode *cur_node = arena->state->first_node, *next = cur_node->next;
    while (next != NULL) {
        cur_node = next;
        next = next->next;
        arena->free(cur_node);
    }
    
    size_t node_size = sizeof(ArenaNode) + arena->state->first_node->size;
    memset(arena->state->first_node, 0, node_size);
}

/* Returns allocated space in the current context arena containing a copy of
 * (len) bytes of the given string (null terminator is appended) */
static inline char *arena_alloc_string(Arena *a, const char *str, size_t len) {
    char *s = arena_alloc(a, (len + 1) * sizeof(char));
    s[len] = '\0';
    return memcpy(s, str, len);
}

/* Returns allocated space in the current context arena containing a copy of
 * the provided C-string */
static inline char *arena_alloc_c_string(Arena *a, const char *str) {
    size_t bytes = 0;
    while (*(str + bytes++));

    char *buf = (char*)arena_alloc(a, bytes);
    size_t idx = 0;
    while((*(buf + idx) = *(str + idx))) idx++;

    return buf;
}

/* Returns a pointer to the first character of an allocated string inside
 * [arena] with a format defined by [fmt] */
static inline char *arena_sprintf(Arena *arena, const char *fmt, ...) {
    va_list args, args2;
    va_start(args, fmt);
    va_copy(args2, args);

    size_t bytes = vsnprintf(NULL, 0 , fmt, args) + 1;
    va_end(args);

    char *s = arena_alloc_align(arena, bytes, CA_DEFAULT_ALIGNMENT);
    if (s == NULL) return NULL;

    vsprintf(s, fmt, args2);
    va_end(args2);

    return s;
}

/* ---------- Stack Allocator Section ---------- */
typedef struct Stack {
    unsigned char *buf;
    size_t size;
    size_t offset;
    struct Stack *next;
    void *(*alloc)(size_t);
    void (*free)(void*);
} Stack;

typedef struct StackHeader {
    size_t padding;
} StackHeader;

#define CA_STACK_INIT_SIZE CA_PAGE_SIZE

static inline Stack *stack_init( 
    size_t initial_size,
    void *(*backing_allocator)(size_t),
    void (*backing_deallocator)(void*)
) {
    if (initial_size == 0) initial_size = CA_STACK_INIT_SIZE;

    if (backing_allocator == NULL && backing_deallocator == NULL) {
        backing_allocator = page_alloc;
        backing_deallocator = page_free; 
    } else if (backing_allocator == NULL || backing_deallocator == NULL) {
        return NULL;
    }

    Stack *stack = backing_allocator(sizeof(*stack) + initial_size);
    if (stack == NULL) return NULL;

    stack->buf = (unsigned char*)(stack + 1); 
    stack->alloc = backing_allocator;
    stack->free = backing_deallocator;
    stack->size = initial_size;

    return stack;
}

/* Aligns a pointer forward accounting for both the size
 * of a header and the alignment */
static inline size_t _ca_get_header_padding(
    uintptr_t ptr,
    uintptr_t align,
    size_t header_size
) {
    assert(_ca_is_power_of_two(align));

    uintptr_t a = align;
    uintptr_t mod = ptr & (a - 1);
    uintptr_t padding = mod ? a - mod : 0;
    uintptr_t needed_space = (uintptr_t)header_size;
    if (padding < needed_space) {
        needed_space -= padding;
        padding += (needed_space & (a - 1)) ?
            a * (needed_space / a + 1) : a * (needed_space / a);
    }

    return (size_t)padding;
}

void *stack_alloc_align(Stack *stack, size_t size, size_t align) {
    (void)stack,(void)size,(void)align;
    return NULL;
}

#endif /* _CYALLOC_H */
