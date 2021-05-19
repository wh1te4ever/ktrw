#ifndef OFFSETS
#define OFFSETS

#include <stdbool.h>
#include <stdint.h>

extern uint64_t g__disable_preemption_addr;
extern uint64_t g__enable_preemption_addr;
extern uint64_t g_const_boot_args_addr;
extern uint64_t g_IOSleep_addr;
extern uint64_t g_kernel_map_addr;
extern uint64_t g_kernel_memory_allocate_addr;
extern uint64_t g_kernel_thread_start_addr;
extern uint64_t g_ml_nofault_copy_addr;
extern uint64_t g_panic_addr;
extern uint64_t g_thread_deallocate_addr;
extern uint64_t g_vsnprintf_addr;

extern bool g_did_patch_slidePrelinkedExecutable;

#endif
