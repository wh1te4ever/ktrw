#ifndef PF14
#define PF14

#include <stdbool.h>

typedef struct xnu_pf_patch xnu_pf_patch_t;

bool OSKext_init_patcher_14(xnu_pf_patch_t *, void *);
bool ktrr_lockdown_patcher_14(xnu_pf_patch_t *, void *);
bool amcc_ctrr_lockdown_patcher_14(xnu_pf_patch_t *, void *);
bool IOSleep_finder_14(xnu_pf_patch_t *, void *);
bool kernel_map_finder_14(xnu_pf_patch_t *, void *);
bool kernel_thread_start_thread_deallocate_finder_14(xnu_pf_patch_t *, void *);
bool panic_finder_14(xnu_pf_patch_t *, void *);
bool const_boot_args_finder_14(xnu_pf_patch_t *, void *);
bool _disable_enable_preemption_finder_14(xnu_pf_patch_t *, void *);
bool vsnprintf_finder_14(xnu_pf_patch_t *, void *);
bool ml_nofault_copy_finder_14(xnu_pf_patch_t *, void *);

#endif
