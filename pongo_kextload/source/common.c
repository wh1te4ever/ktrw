#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "common.h"

/* XXX do not panic so user can see what screen says */
__attribute__ ((noreturn)) void ktrw_fatal_error(void){
    puts("KTRW: fatal error.");
    puts("     Please file an issue");
    puts("     on this fork's Github. Include");
    puts("     output up to this");
    puts("     point and device/iOS");
    puts("     version.");
    puts("Spinning forever.");

    for(;;);
}

// Extract bits from an integer.
uintmax_t bits(uintmax_t x, unsigned sign, unsigned hi, unsigned lo,
        unsigned shift) {
	const unsigned bits = sizeof(uintmax_t) * 8;
	unsigned d = bits - (hi - lo + 1);
	if (sign) {
		return (uintmax_t) (((((intmax_t)  x) >> lo) << d) >> (d - shift));
	} else {
		return (((((uintmax_t) x) >> lo) << d) >> (d - shift));
	}
}

// Test whether the instruction matches the specified pattern.
bool MATCH(uint32_t insn, uint32_t match, uint32_t mask) {
	return ((insn & mask) == match);
}

// Resolve an ADRP/ADD instruction sequence to the pointer to the target value.
void *RESOLVE_ADRP_ADD(uint32_t *insn) {
	uint32_t adrp = insn[0];
	uint32_t add  = insn[1];
	// All registers must match. Also disallow SP.
	unsigned reg0 = (unsigned) bits(adrp, 0, 4, 0, 0);
	unsigned reg1 = (unsigned) bits(add,  0, 4, 0, 0);
	unsigned reg2 = (unsigned) bits(add,  0, 9, 5, 0);
	if (reg0 != reg1 || reg1 != reg2 || reg0 == 0x1f) {
		return NULL;
	}
	// Compute the target address.
	uint64_t pc = va_for_ptr(&insn[0]);
	uint64_t imm0 = bits(adrp, 1, 23, 5, 12+2) | bits(adrp, 0, 30, 29, 12);
	uint64_t imm1 = bits(add, 0, 21, 10, 0);
	uint64_t target = (pc & ~0xFFFuLL) + imm0 + imm1;
	return ptr_for_va(target);
}

/* no sign support */
int atoi(const char *s){
    int res = 0;

    while(*s){
        res = res * 10 + (*s - '0');
        s++;
    }

    return res;
}
