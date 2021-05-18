#ifndef PFS
#define PFS

#include "pf_common.h"

#include "14/pf.h"

#define MAXPF                       (50)
#define NUM_SUPPORTED_VERSIONS      (1)

#define PFS_END(x) (x[0].pf_unused == 0x41)
#define IS_PF_UNUSED(x) (x->pf_unused == 1)

/* Format:
 *
 * { iOS 14 patchfinder }
 *
 * This array will end with
 * { PF_END }
 */
struct pf g_all_pfs[MAXPF][NUM_SUPPORTED_VERSIONS] = {
    /* XXX Start original KTRW patchfinders */
    {
        PF_DECL32("OSKext::initWithPrelinkedInfoDict patcher iOS 14",
                LISTIZE({
                    0xF9400000,	// [0]  LDR  Xn, [Xn]
                    0xF9400000,	// [1]  LDR  Xn, [Xn,#0xNNN]		;; 0xNNN < 0x200
                    0x90000001,	// [2]  ADRP X1, #0xNNN
                    0x91000021,	// [3]  ADD  X1, X1, #0xNNN		;; 0xNNN < 2^(12)
                    0xAA0003E0,	// [4]  MOV  X0, Xn
                    0xD63F0000,	// [5]  BLR  Xn
                }),
                LISTIZE({
                    0xFFFFFC00,	// [0]  LDR
                    0xFFFF0000,	// [1]  LDR
                    0x9F00001F,	// [2]  ADRP
                    0xFFC003FF,	// [3]  ADD
                    0xFFE0FFFF,	// [4]  MOV
                    0xFFFFFC1F,	// [5]  BLR
                }),
                6, OSKext_init_patcher_14, "__TEXT_EXEC"),
    },
    /* XXX End original KTRW patchfinders */
    {
        PF_DECL32("KTRR MMU lockdown patcher iOS 14",
            LISTIZE({
                0xd51cf260,     /* msr s3_4_c15_c2_3, xn */
                0xd51cf280,     /* msr s3_4_c15_c2_4, xn */
                0x52800020,     /* mov (x|w)n, 1 */
                0xd51cf240,     /* msr s3_4_c15_c2_2, xn */
            }),
            LISTIZE({
                0xffffffe0,     /* ignore Rt */
                0xffffffe0,     /* ignore Rt */
                0x7fffffe0,     /* ignore Rd */
                0xffffffe0,     /* ignore Rt */
            }),
            4, ktrr_lockdown_patcher_14, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("AMCC CTRR MMU lockdown patcher iOS 14",
            LISTIZE({
                0xb94001d1,     /* ldr w17, [x14] */
                0x1b0f7e31,     /* mul x17, w17, w15 */
                0x8b110210,     /* add x16, x16, x17 */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0xb8316a00,     /* str w0, [x16, x17] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* match exactly */
            }),
            6, amcc_ctrr_lockdown_patcher_14, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("IOSleep finder iOS 14",
            LISTIZE({
                0x52884801,     /* mov w1, 0x4240 */
                0x72a001e1,     /* movk w1, 0xf, lsl 16 */
                0x14000000,     /* b _delay_for_interval */
                0x52884802,     /* mov w2, 0x4240 */
                0x72a001e2,     /* movk w2, 0xf, lsl 16 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            5, IOSleep_finder_14, "__TEXT_EXEC"),
    },
    /* XXX: only need kernel_map from this */
    {
        PF_DECL_FULL("kernel_map finder iOS 14",
            LISTIZE({
                0x94000000,     /* bl _vm_map_unwire */
                0xf94002e0,     /* ldr x0, [x23] */
                0xa9400a61,     /* ldp x1, x2, [x19] */
                0x94000000,     /* bl _vm_deallocate */
                0xa9402668,     /* ldp x8, x9, [x19] */
                0x8b090114,     /* add x20, x8, x9 */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            6, XNU_PF_ACCESS_32BIT,
            kernel_map_finder_14,
            "com.apple.security.sandbox", "__TEXT_EXEC", NULL),
    },
    {
        PF_DECL_FULL("kernel_thread_start,thread_deallocate finder iOS 14",
            LISTIZE({
                0x94000000,     /* bl _kernel_thread_start */
                0x34000000,     /* cbz w0, n */
                0xf900027f,     /* str xzr, [x19] */
                0x528000a0,     /* mov w0, 5 */
                0xa9417bfd,     /* ldp x29, x30, [sp, 0x10] */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0xff00001f,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            5, XNU_PF_ACCESS_32BIT,
            kernel_thread_start_thread_deallocate_finder_14,
            "com.apple.filesystems.apfs", "__TEXT_EXEC", NULL),
    },
    {
        PF_DECL32("panic finder iOS 14",
            LISTIZE({
                0x910023e1,     /* add x1, sp, #8 */
                0x52800002,     /* mov w2, #0 */
                0xd2800003,     /* mov x3, #0 */
                0xd2800004,     /* mov x4, #0 */
                0xd2800005,     /* mov x5, #0 */
                0xaa1e03e6      /* mov x6, x30 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            6, panic_finder_14, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("const_boot_args finder iOS 14",
            LISTIZE({
                0xd500419f,     /* msr PAN, #1 */
                0x10000001,     /* adrp x1, n or adr x1, n */
                0x0,            /* ignore this instruction */
                0xaa1303e0,     /* mov x0, x19 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* match exactly */
            }),
            4, const_boot_args_finder_14, "__TEXT_EXEC"),

    },
    {
        PF_DECL32("_disable_preemption/_enable_preemption finder iOS 14",
            LISTIZE({
                0x910003fd,     /* mov x29, sp */
                0xd538d088,     /* mrs x8, tpidr_el1 */
                0xb9400109,     /* ldr w9, [x8, n] */
                0x31000529,     /* adds w9, w9, #1 */
                0x54000002,     /* b.cs n */
                0xb9000109,     /* str w9, [x8, n] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffc003ff,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xff00001f,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
            }),
            6, _disable_enable_preemption_finder_14, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("vsnprintf finder iOS 14",
            LISTIZE({
                0xaa0303e8,     /* mov x8, x3 */
                0xaa0203e9,     /* mov x9, x2 */
                0xa90007e0,     /* stp x0, x1, [sp] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            3, vsnprintf_finder_14, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("ml_nofault_copy finder iOS 14",
            LISTIZE({
                0x8b130313,     /* add x19, x24, x19 */
                0x8b160316,     /* add x22, x24, x22 */
                0x8b150315,     /* add x21, x24, x21 */
                0xeb180294,     /* subs x20, x20, x24 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            4, ml_nofault_copy_finder_14, "__TEXT_EXEC"),
    },
    { PF_END, },
};

#endif
