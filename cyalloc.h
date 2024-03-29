#ifndef _CYALLOC_H
#define _CYALLOC_H

#include <stdio.h>   // for optional logging
#include <stdint.h>  // uintptr_t and size_t
#include <stdbool.h> // bool
#include <string.h>  // memcpy and memset
#include <assert.h>  // assertions

#define CA_DEFAULT_ALIGNMENT (2 * sizeof(void*))

static inline bool _ca_is_power_of_two(uintptr_t n) {
    return (n & (n - 1)) == 0;
}

static inline uintptr_t _ca_mem_align_forward(uintptr_t ptr, size_t align) {
    assert(_ca_is_power_of_two(align));

    uintptr_t mod = ptr & (align - 1);
    if (mod) ptr += align - mod;

    return ptr;
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

/* Returns the total size of the page(s) reserved by the OS (including chunk) */
static inline size_t _ca_page_get_size(void *ptr) {
    PageChunk *chunk = (PageChunk*)((char*)ptr - sizeof(*chunk));
    return chunk->size;
}

/* Immediately returns the allocated memory starting @ [ptr] back to the OS */
static inline void page_free(void *ptr) {
    /* All allocated pages will have a metadata chunk right before the
     * beginning of the pointer that must be stepped back into
     * in order to free the whole block -> [*...[PageChunk][ptr]...] */
    PageChunk *chunk = (PageChunk*)((char*)ptr - sizeof(*chunk));
    const size_t chunk_aligned_size = 
        (size_t)_ca_mem_align_forward(sizeof(*chunk), chunk->align);
#ifdef _WIN32
    VirtualFree(ptr, 0, MEM_RELEASE);
#else
    munmap((char*)ptr - chunk_aligned_size, chunk->size);
#endif
}

static inline void *page_realloc_align(
    void *ptr,
    size_t new_size,
    size_t align
) {
    PageChunk *chunk = (PageChunk*)((char*)ptr - sizeof(*chunk));
    const size_t new_aligned_size =
        _ca_mem_align_forward(new_size, align);
    const size_t current_size = _ca_page_get_size(ptr);
    const size_t chunk_aligned_size = 
        (size_t)_ca_mem_align_forward(sizeof(*chunk), chunk->align);

    /* TODO: free excess pages if possible
     * (free memory) starting at
     * (current_size - new_aligned_size + chunk_aligned_size) */
    if (new_aligned_size + chunk_aligned_size <= current_size) {
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

/* ---------- Arena Allocator Section ---------- */
typedef struct Arena {
    unsigned char *buf;     // actual arena memory
    size_t size;            // size of the buffer in bytes
    size_t pos;             // offset to first byte of (unaligned) free memory
    struct Arena *next;     // pointer to next arena (linked-list of arenas)
    void *(*alloc)(size_t); // backing allocator
    void (*free)(void*);    // backing deallocator
} Arena;

/* TODO: 
 *  1. consider moving the allocator/deallocator pair to a config struct
 *  2. consider dropping the whole 'context arena' logic */

static Arena *context = NULL;

/* Default initial size set to one page */
#define CA_ARENA_INIT_SIZE     CA_PAGE_SIZE
#define CA_ARENA_GROWTH_FACTOR 2.0

/* Sets the arena to be used by arena_alloc(), arena_flush(), arena_deinit() */
static inline void arena_set_context(Arena *arena) {
    context = arena; 
}

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
        fprintf(stderr, "FATAL: incomplete allocator/deallocator pair provided"
            " to arena allocator.\n");
        return NULL;
    }
    
    Arena *arena = backing_allocator(sizeof(*arena) + initial_size);
    if (arena == NULL) {
        fprintf(stderr, "FATAL: unable to initialize arena of %zuB\n",
            initial_size);
        return NULL;
    }

    arena->buf = (unsigned char*)(arena + 1); 
    arena->alloc = backing_allocator;
    arena->free = backing_deallocator;
    arena->size = initial_size;

    return arena;
}

/* Initializes a new arena and sets it as the current context */
static inline Arena *arena_init_set_context(
    size_t initial_size,
    void *(*backing_allocator)(size_t),
    void (*backing_deallocator)(void*)
) {
    Arena *arena = arena_init(initial_size,
        backing_allocator, backing_deallocator);    
    arena_set_context(arena);
    return arena;
}

static inline void *_ca_arena_alloc_align(
    Arena *arena,
    size_t bytes,
    size_t align
) {
    arena->pos = _ca_mem_align_forward(arena->pos, CA_DEFAULT_ALIGNMENT);
    if (arena->pos + bytes > arena->size) {
        /* need more memory! (make growable arena linked list) */
        if (arena->next == NULL) {
            size_t new_size = (size_t)(arena->size * CA_ARENA_GROWTH_FACTOR);
            if (bytes > new_size) {
                fprintf(stderr,
                    "FATAL: requested block won't fit in a single arena!"
                    " (Block: %zuB, Arena: %zuB)\n", bytes, arena->size);
                return NULL;
            }

#ifdef CA_LOGGING
            fprintf(stderr, "ALLOCATING: new arena of %zuB...\n\n", new_size);
#endif
            arena->next = arena_init(new_size, arena->alloc, arena->free);
            return _ca_arena_alloc_align(arena->next, bytes, align);
        }

        return _ca_arena_alloc_align(arena->next, bytes, align);
    }

    size_t pos = arena->pos;
    arena->pos += bytes;

    return (void*)(arena->buf + pos);
}

static inline void *arena_alloc_align(size_t bytes, size_t alignment) {
    if (context == NULL) context = arena_init(CA_ARENA_INIT_SIZE, NULL, NULL);

    return _ca_arena_alloc_align(context, bytes, alignment);
}

/* Returns a suitable place in memory for a buffer of the given size in bytes,
 * from somewhere within the current context arena */
static inline void *arena_alloc(size_t bytes) {
    return arena_alloc_align(bytes, CA_DEFAULT_ALIGNMENT);
}

static inline void _ca_arena_deinit(Arena *arena) {
    if (arena->next != NULL) {
        _ca_arena_deinit(arena->next);
    }

#ifdef CA_LOGGING
    fprintf(stderr, "RELEASING: arena @ 0x%p...\n\n", (void*)arena->buf);
#endif

    arena->free(arena);
}

/* Frees all resources allocated by the arena, including itself */
static inline Arena *arena_deinit(void) {
    _ca_arena_deinit(context);
    context = NULL;
    return context;
}

/* Frees all the excess allocations done by the current context arena and
 * clears all of its space to zero */
static inline void arena_flush(void) {
    if (context == NULL) return;
    
    if (context->next != NULL) {
        _ca_arena_deinit(context->next);
    }

    context->pos = 0;
    context->next = NULL;
    memset(context->buf, 0, context->size);
}

/* Returns allocated space in the current context arena containing a copy of
 * (len) bytes of the given string (null terminator is appended) */
static inline char *arena_alloc_string(const char *str, size_t len) {
    char *s = arena_alloc((len + 1) * sizeof(char));
    s[len] = '\0';
    return memcpy(s, str, len);
}

/* Returns allocated space in the current context arena containing a copy of
 * the provided C-string */
static inline char *arena_alloc_c_string(const char *str) {
    size_t bytes = 0;
    while (*(str + bytes++));

    char *buf = (char*)arena_alloc(bytes);
    size_t idx = 0;
    while((*(buf + idx) = *(str + idx))) idx++;

    return buf;
}

// TODO: remake this
// static inline char *ArenaSprintf(Arena *arena, const char *format, ...) {
//     va_list args;
//     va_start(args, format);
//     size_t bytes = vsnprintf(NULL, 0 , format, args) + 1;
//     char *s = ArenaPush(arena, bytes * sizeof(char));
//     va_end(args);
// 
//     va_start(args, format);
//     vsprintf(s, format, args);
//     va_end(args);
// 
//     return s;
// }
// 

#endif /* _CYALLOC_H */
