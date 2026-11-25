#ifndef UNPACK_CORE_H
#define UNPACK_CORE_H
#include <stddef.h>
#include <stdint.h>

/* Buffers belong to handle and remain valid until unpack_core_result_free. */
typedef struct {
    const uint8_t *metadata;
    size_t metadata_len;
    const uint8_t *data;
    size_t data_len;
    void *handle;
} unpack_result;

void *unpack_core_context_new(void);
/* May run concurrently with unpack_core_call; free only after the call returns. */
void unpack_core_context_cancel(void *context);
void unpack_core_context_free(void *context);
unpack_result unpack_core_call(const uint8_t *request, size_t length, const void *context);
void unpack_core_result_free(void *handle);
#endif
