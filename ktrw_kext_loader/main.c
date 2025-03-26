#include <stdio.h>

#include "kernel_call.h"
#include "kernel_memory.h"
#include "kernel_patches.h"
#include "kext_load.h"
#include "ktrr_bypass.h"
#include "log.h"
#include <unistd.h>
#include <inttypes.h>

task_t tfp0 = MACH_PORT_NULL;

static kern_return_t
init_kernrw(void) {
	kern_return_t ret = task_for_pid(mach_task_self(), 0, &tfp0);
	mach_port_t host;
	pid_t pid;

	if(ret != KERN_SUCCESS) {
		host = mach_host_self();
		if(MACH_PORT_VALID(host)) {
			printf("host: 0x%" PRIx32 "\n", host);
			ret = host_get_special_port(host, HOST_LOCAL_NODE, 4, &tfp0);
			mach_port_deallocate(mach_task_self(), host);
		}
	}
	if(ret == KERN_SUCCESS && MACH_PORT_VALID(tfp0)) {
		if(pid_for_task(tfp0, &pid) == KERN_SUCCESS && pid == 0) {
			return ret;
		}
		mach_port_deallocate(mach_task_self(), tfp0);
	}

	return KERN_FAILURE;
}

int main(int argc, const char *argv[]) {
	int ret = 1;
	// Parse arguments.
	if (argc != 2) {
		printf("usage: %s <kext-path>\n", argv[0]);
		goto done_0;
	}
	const char *kext_path = argv[1];
	// Load the kernel symbol database.
	bool ok = kext_load_set_kernel_symbol_database("kernel_symbols");
	if (!ok) {
		ERROR("Could not load kernel symbol database");
		goto done_0;
	}
	// Try to get the kernel task port using task_for_pid().
	kernel_task_port = MACH_PORT_NULL;
	if(init_kernrw() != KERN_SUCCESS) {
		ERROR("Could not get kernel task port");
		goto done_0;
	}
	kernel_task_port = tfp0;
	INFO("task_for_pid(0) = 0x%x", kernel_task_port);
	// Initialize our kernel function calling capability.
	ok = kernel_call_init();
	if (!ok) {
		ERROR("Could not initialize kernel_call subsystem");
		goto done_0;
	}
	// TODO: Check if we've already bypassed KTRR.
	// Ensure that we have a KTRR bypass.
	ok = have_ktrr_bypass();
	if (!ok) {
		ERROR("No KTRR bypass is available for this platform");
		goto done_1;
	}
	// Bypass KTRR and remap the kernel as read/write.
	ktrr_bypass();
	// Apply kernel patches.
	apply_kernel_patches();
	// Load the kernel extension.
	uint64_t kext_address = kext_load(kext_path, 171);
	if (kext_address == 0) {
		ERROR("Could not load kext %s", kext_path);
		goto done_1;
	}
	INFO("Kext %s loaded at address 0x%016llx", kext_path, kext_address);
	ret = 0;
done_1:
	// De-initialize our kernel function calling primitive.
	kernel_call_deinit();
done_0:
	return ret;
}
