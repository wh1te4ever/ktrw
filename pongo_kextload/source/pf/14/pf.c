#include <stdio.h>
#include <stdint.h>

#include "../offsets.h"

#include "../../asm.h"
#include "../../common.h"

#include "../../third_party/pongo.h"

/* XXX Start original KTRW patchfinders */
bool OSKext_init_patcher_14(xnu_pf_patch_t *patch, void *cacheable_stream) {
	const int MAX_SEARCH = 300;
	uint32_t *insn = cacheable_stream;
	// First we need to resolve the ADRP/ADD target at [2].
	void *target = RESOLVE_ADRP_ADD(&insn[2]);
	if (target == NULL) {
		return false;
	}
	// Check if the target is "_PrelinkBundlePath", which indicates that this function is
	// OSKext::initWithPrelinkedInfoDict(). Bailing here is the most common path.
	if (strcmp(target, "_PrelinkBundlePath") != 0) {
		return false;
	}
	puts("Patching OSKext::initWithPrelinkedInfoDict()");
	// Search backwards until we get the prologue. Record the instruction that MOVs from X2.
	uint32_t *x2_insn = NULL;
	for (int i = 0;; i--) {
		if (i < -MAX_SEARCH) {
			return false;
		}
		// Check for either of the following instructions, signaling we hit the prologue:
		// 	SUB  SP, SP, #0xNNN		;; 0xNNN < 0x400
		// 	STP  X28, X27, [SP,#0xNNN]	;; 0xNNN < 0x100
		bool prologue = MATCH(insn[i], 0xD10003FF, 0xFFF01FFF)
			|| MATCH(insn[i], 0xA9006FFC, 0xFFC0FFFF);
		if (prologue) {
			break;
		}
		// Check for the instruction that saves argument X2, doCoalesedSlides:
		// 	MOV  Xn, X2
		bool mov_xn_x2 = MATCH(insn[i], 0xAA0203E0, 0xFFFFFFE0);
		if (mov_xn_x2) {
			x2_insn = &insn[i];
		}
	}
	// Check that we found the target instruction.
	if (x2_insn == NULL) {
		return false;
	}
	// Patch the instruction to zero out doCoalesedSlides:
	// 	MOV  Xn, XZR
	*x2_insn |= 0x001F0000;
    puts("KTRW: Patched OSKext::initWithPrelinkedInfoDict");
	// We no longer need to match this. Disabling the patch speeds up execution time, since the
	// pattern is pretty frequent.
	xnu_pf_disable_patch(patch);
	return true;
}

/* XXX End original KTRW patchfinders */

/* confirmed working on all KTRR kernels 14.0-14.5 */
bool ktrr_lockdown_patcher_14(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* This also hits rorgn_lockdown, where the AMCC CTRR patches are,
     * but it's easier for me to separate them since the instruction
     * sequences are so different */
    static int count = 1;
    uint32_t *opcode_stream = cacheable_stream;

    *opcode_stream = 0xd503201f;
    opcode_stream[1] = 0xd503201f;
    opcode_stream[3] = 0xd503201f;

    if(count == 2){
        xnu_pf_disable_patch(patch);
        puts("KTRW: disabled KTRR MMU lockdown");
    }

    count++;

    return true;
}

/* confirmed working on all KTRR kernels 14.0-14.5 */
bool amcc_ctrr_lockdown_patcher_14(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* On 14.x A10+ there doesn't seem to be a specific lock for
     * RoRgn, instead we've got these AMCC CTRR registers. We are
     * patching three of them: lock, enable, and write-disable. See
     * find_lock_group_data and rorgn_lockdown for more info. */
    static int count = 1;
    uint32_t *opcode_stream = cacheable_stream;

    /* str w0, [x16, x17] --> str wzr, [x16, x17] */
    opcode_stream[5] = 0xb8316a1f;

    if(count == 3){
        xnu_pf_disable_patch(patch);
        puts("KTRW: disabled AMCC CTRR MMU lockdown");
    }

    count++;

    return true;
}

/* confirmed working on all kernels 13.0-14.5 */
bool IOSleep_finder_14(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    g_IOSleep_addr = xnu_ptr_to_va(cacheable_stream);

    puts("KTRW: found IOSleep");

    return true;
}

/* confirmed working on all kernels 13.0-14.5 */
bool kernel_map_finder_14(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    /* If we're 13.x, we've landed inside profile_release, if we're 14.x,
     * we've landed inside _profile_destroy. For vm_map_unwire, it'll be the
     * branch we're currently sitting at. */
    uint32_t *opcode_stream = cacheable_stream;

    /* Finally, we can find kernel_map by searching up for the first ADRP
     * or ADR from where we initially landed */
    uint32_t instr_limit = 150;

    while((*opcode_stream & 0x1f000000) != 0x10000000){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    /* The ADRP,LDR pairs require another level of indirection for this */
    if(((opcode_stream[1] >> 25) & 5) == 4){
        g_kernel_map_addr = *(uint64_t *)get_adrp_ldr_target(opcode_stream);
        g_kernel_map_addr |= ((uint64_t)0xffff << 48);
        g_kernel_map_addr = kext_rebase_va(g_kernel_map_addr);
    }
    else{
        uint64_t kernel_map_addr;

        if(*opcode_stream & 0x80000000)
            kernel_map_addr = get_adrp_add_target(opcode_stream);
        else
            kernel_map_addr = get_adr_target(opcode_stream);

        g_kernel_map_addr = xnu_ptr_to_va((void *)kernel_map_addr);
    }

    puts("KTRW: found kernel_map");

    return true;
}

/* confirmed working on all kernels 13.0-14.5 */
bool kernel_thread_start_thread_deallocate_finder_14(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* There's two hits for this, but they're identical, so whatever is
     * matched first will do */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *kernel_thread_start = get_branch_dst_ptr(opcode_stream);
    uint32_t *thread_deallocate = get_branch_dst_ptr(opcode_stream + 8);

    g_kernel_thread_start_addr = xnu_ptr_to_va(kernel_thread_start);
    g_thread_deallocate_addr = xnu_ptr_to_va(thread_deallocate);

    puts("KTRW: found kernel_thread_start");
    puts("KTRW: found thread_deallocate");

    return true;
}

/* confirmed working on all kernels 13.0-14.5 */
bool panic_finder_14(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    /* Look for the start of panic's prologue, trying to match
     * sub sp, sp, n */
    uint32_t instr_limit = 50;

    while((*opcode_stream & 0xffc003ff) != 0xd10003ff){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    g_panic_addr = xnu_ptr_to_va(opcode_stream);

    puts("KTRW: found panic");

    return true;
}

bool const_boot_args_finder_14(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* I don't know where we landed but const_boot_args is the target
     * of the ADRP/ADD one instruction down */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint64_t const_boot_args = get_pc_rel_target(opcode_stream + 1);
    g_const_boot_args_addr = xnu_ptr_to_va(const_boot_args);

    puts("KTRW: found const_boot_args");

    return true;
}

bool _disable_enable_preemption_finder_14(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* We may have landed inside _disable_preemption. The only way
     * we can tell is if there's a clrex #0xf less than ten instructions up,
     * so look for that. */
    uint32_t *opcode_stream = cacheable_stream;
    uint32_t instr_limit = 10;

    while(*opcode_stream != 0xd5033f5f){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    xnu_pf_disable_patch(patch);

    instr_limit = 10;

    /* The clrex #0xf is there, go forward for the start of
     * _disable_preemption. Looking for stp x29, x30, [sp, #-0x10]! */
    while(*opcode_stream != 0xa9bf7bfd){
        if(instr_limit-- == 0)
            return false;

        opcode_stream++;
    }

    g__disable_preemption_addr = xnu_ptr_to_va(opcode_stream);

    /* _enable_preemption is right under _disable_preemption, so
     * we grab that also */
    instr_limit = 25;

    /* The clrex #0xf is there, go forward for the start of
     * _disable_preemption. Looking for stp x29, x30, [sp, #-0x10]! */
    while(*opcode_stream != 0xa9bf7bfd){
        if(instr_limit-- == 0)
            return false;

        opcode_stream++;
    }

    g__enable_preemption_addr = xnu_ptr_to_va(opcode_stream);

    puts("KTRW: found _disable_preemption");
    puts("KTRW: found _enable_preemption");

    return true;
}

bool vsnprintf_finder_14(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* We landed in vsnprintf, find its prolouge. Searching for
     * sub sp, sp, n */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;
    uint32_t instr_limit = 50;

    while((*opcode_stream & 0xffc003ff) != 0xd10003ff){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    g_vsnprintf_addr = xnu_ptr_to_va(opcode_stream);

    puts("KTRW: found vsnprintf");

    return true;
}

bool ml_nofault_copy_finder_14(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* We landed inside ml_nofault_copy so we need to find its
     * prologue. Searching for stp x28, x27, [sp, #-0x60]! */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;
    uint32_t instr_limit = 200;

    while(*opcode_stream != 0xa9ba6ffc){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    g_ml_nofault_copy_addr = xnu_ptr_to_va(opcode_stream);

    puts("KTRW: found ml_nofault_copy");

    return true;
}
