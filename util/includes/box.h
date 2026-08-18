#ifndef BOX_H
#define BOX_H

#include <stdint.h>

/* forward declaration of `box_t` type declared within box.c */
typedef struct box_t box_t;

/* on success, allocates a box_t structure with an internal data allocation of (size * count) or NULL on failure */
box_t *box_new(uint32_t count, uint32_t size);

/* frees box_t and underlying data */
void box_free(box_t **box);

/* exposes a reference to the internal data pointer */
void *box_data(const box_t *box);

/* returns total size allocated during box_new(), if not initialized, returns 0 */
uint32_t box_size(const box_t *box);

#endif