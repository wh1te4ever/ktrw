#ifndef COMMON
#define COMMON

#include <mach-o/loader.h>
#include <stdbool.h>
#include <stdint.h>

extern struct mach_header_64 *mh_execute_header;
extern uint64_t kernel_slide;

#define sa_for_va(va)	((uint64_t) (va) - kernel_slide)
#define va_for_sa(sa)	((uint64_t) (sa) + kernel_slide)
#define ptr_for_sa(sa)	((void *) (((sa) - 0xFFFFFFF007004000uLL) + (uint8_t *) mh_execute_header))
#define ptr_for_va(va)	(ptr_for_sa(sa_for_va(va)))
#define sa_for_ptr(ptr)	((uint64_t) ((uint8_t *) (ptr) - (uint8_t *) mh_execute_header) + 0xFFFFFFF007004000uLL)
#define va_for_ptr(ptr)	(va_for_sa(sa_for_ptr(ptr)))
#define pa_for_ptr(ptr)	(sa_for_ptr(ptr) - gBootArgs->virtBase + gBootArgs->physBase)

#define isdigit(c) (c >= '0' && c <= '9')

void ktrw_fatal_error(void);
uintmax_t bits(uintmax_t, unsigned, unsigned, unsigned, unsigned);
bool MATCH(uint32_t, uint32_t, uint32_t);
void *RESOLVE_ADRP_ADD(uint32_t *);
int atoi(const char *);


#endif
