//
// Project: KTRW
// Author:  Brandon Azad <bazad@google.com>
//
// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include <stdio.h>
#include <stdlib.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>

#include "third_party/pongo.h"
#include "common.h"
#include "pf/pf_common.h"
#include "pf/pfs.h"

// ---- Configuration -----------------------------------------------------------------------------

#define DISABLE_CHECKRA1N_KERNEL_PATCHES 0

// ---- Standard functions ------------------------------------------------------------------------

#undef memcmp
#define memcmp memcmp_
static int
memcmp(const void *s1, const void *s2, size_t n) {
	int diff = 0;
	for (size_t i = 0; diff == 0 && i < n; i++) {
		diff = ((uint8_t *) s1)[i] - ((uint8_t *) s2)[i];
	}
	return diff;
}

#undef memset

#undef strcpy

#undef strnlen
#define strnlen strnlen_
static size_t
strnlen(const char *s, size_t n) {
	size_t len = 0;
	while (len < n && s[len] != 0) {
		len++;
	}
	return len;
}

// ---- Pointer conversions -----------------------------------------------------------------------

struct mach_header_64 *mh_execute_header;
uint64_t kernel_slide;

// ---- Symbol table ------------------------------------------------------------------------------

uint64_t g__disable_preemption_addr = 0;
uint64_t g__enable_preemption_addr = 0;
uint64_t g_const_boot_args_addr = 0;
uint64_t g_IOSleep_addr = 0;
uint64_t g_kernel_map_addr = 0;
uint64_t g_kernel_memory_allocate_addr = 0;
uint64_t g_kernel_thread_start_addr = 0;
uint64_t g_ml_nofault_copy_addr = 0;
uint64_t g_paniclog_append_noflush_addr = 0;
uint64_t g_panic_addr = 0;
uint64_t g_thread_deallocate_addr = 0;
uint64_t g_vsnprintf_addr = 0;

bool g_did_patch_slidePrelinkedExecutable = false;

/* Constants */
static uint64_t g_mhaddr = 0xfffffff007004000;

static struct kcsym {
    const char *name;
    uint64_t *val;
} g_kcsyms[] = {
    { "__disable_preemption", &g__disable_preemption_addr },
    { "__enable_preemption", &g__enable_preemption_addr },
    { "__mh_execute_header", &g_mhaddr },
    { "_const_boot_args", &g_const_boot_args_addr },
    { "_IOSleep", &g_IOSleep_addr },
    { "_kernel_map", &g_kernel_map_addr },
    { "_kernel_memory_allocate", &g_kernel_memory_allocate_addr },
    { "_kernel_thread_start", &g_kernel_thread_start_addr },
    { "_ml_nofault_copy", &g_ml_nofault_copy_addr },
    { "_paniclog_append_noflush", &g_paniclog_append_noflush_addr },
    { "_panic", &g_panic_addr },
    { "_thread_deallocate", &g_thread_deallocate_addr },
    { "_vsnprintf", &g_vsnprintf_addr },
};

static const size_t g_nkcsyms = sizeof(g_kcsyms) / sizeof(*g_kcsyms);

// Look up the static kernelcache address corresponding to the given named symbol.
static uint64_t
kernelcache_symbol_table_lookup(const char *symbol) {
    for(size_t i=0; i<g_nkcsyms; i++){
        if(strcmp(g_kcsyms[i].name, symbol) == 0){
            /* printf("%s: got val for '%s': %#llx [unslid %#llx]\n", __func__, */
            /*         symbol, *g_kcsyms[i].val, *g_kcsyms[i].val - kernel_slide); */
            /* This will be slid when the kext is linked */
            return *g_kcsyms[i].val - kernel_slide;
        }
    }

	return 0;
}

// ---- Kext loading ------------------------------------------------------------------------------

// The kmod_info struct from XNU.
#pragma pack(push, 4)
struct kmod_info {
	uint64_t next;
	int32_t  info_version;
	uint32_t id;
	char     name[64];
	char     version[64];
	int32_t  reference_count;
	uint64_t reference_list;
	uint64_t address;
	uint64_t size;
	uint64_t hdr_size;
	uint64_t start;
	uint64_t stop;
};
#pragma pack(pop)

// Load information for a kernel extension. Some fields point into the USB buffer.
struct kext_load_info {
	const struct mach_header_64 *header;
	void *kext;
	size_t file_size;
	size_t vm_size;
	uint64_t vm_base;
	struct kmod_info *kmod_info;
	struct symtab_command *symtab;
	struct dysymtab_command *dysymtab;
	const struct nlist_64 *nlist;
	const struct relocation_info *extrel;
	const struct relocation_info *locrel;
};

// Parse the kernel extension Mach-O to validate it and populate the kext_load_info.
static bool
kext_parse(const struct mach_header_64 *header, size_t file_size,
		struct kext_load_info *info) {
	// Basic sanity checks: Mach-O magic, kext type, size is sane, etc.
	if (header->magic != MH_MAGIC_64) {
		puts("Kext is not a 64-bit Mach-O");
		return false;
	}
	if (header->filetype != MH_KEXT_BUNDLE) {
		puts("Mach-O is not a KEXT type");
		return false;
	}
	if (sizeof(*header) + header->sizeofcmds > file_size) {
		puts("Invalid load commands size");
		return false;
	}
	// Store basic load info.
	info->header = header;
	info->file_size = file_size;
	// Iterate the load commands.
	uint64_t vmaddr = 0;
	bool found_first_segment = false;
	struct load_command *lc = (void *) (header + 1);
	uintptr_t lc_end = (uintptr_t) lc + header->sizeofcmds;
	for (uint32_t cmd_idx = 0; cmd_idx < header->ncmds; cmd_idx++) {
		// Check the command size.
		if ((uintptr_t) lc + sizeof(*lc) > lc_end) {
			puts("Invalid load commands");
			return false;
		}
		if ((uintptr_t) lc + lc->cmdsize > lc_end) {
			puts("Invalid load commands");
			return false;
		}
		// Forbid LC_SEGMENT.
		if (lc->cmd == LC_SEGMENT) {
			puts("LC_SEGMENT not permitted");
			return false;
		}
		// Destroy LC_SEGMENT_SPLIT_INFO. I haven't found a way to prevent this segment
		// from being generated during compile.
		if (lc->cmd == LC_SEGMENT_SPLIT_INFO) {
			lc->cmd ^= 0x41000000;
		}
		// Validate this segment. Segments must be contiguous.
		if (lc->cmd == LC_SEGMENT_64) {
			const struct segment_command_64 *sc = (void *) lc;
			if (lc->cmdsize < sizeof(*sc)) {
				puts("LC_SEGMENT_64 bad size");
				return false;
			}
			// Ensure no file overflow.
			if (sc->fileoff > file_size || sc->fileoff + sc->filesize > file_size
					|| sc->filesize > sc->vmsize) {
				puts("LC_SEGMENT_64 bad size");
				return false;
			}
			// Ensure no VM overflow.
			if (sc->vmaddr + sc->vmsize < sc->vmaddr) {
				puts("LC_SEGMENT_64 vm wrap");
				return false;
			}
			// If this is the first segment, set the base address.
			if (!found_first_segment) {
				// This is the first segment.
				found_first_segment = true;
				vmaddr = sc->vmaddr;
				info->vm_base = vmaddr;
				// The first segment must have file offset 0 in order to map the
				// Mach header at vm_base.
				if (sc->fileoff != 0 || sc->filesize < sizeof(*header)
						+ header->sizeofcmds) {
					puts("LC_SEGMENT_64 header not mapped");
					return false;
				}
			}
			// Ensure segments are contiguous.
			if (sc->vmaddr != vmaddr) {
				puts("LC_SEGMENT_64 not contiguous");
				return false;
			}
			vmaddr += sc->vmsize;
		}
		// Validate the symbol table.
		if (lc->cmd == LC_SYMTAB) {
			if (info->symtab != NULL) {
				puts("LC_SYMTAB repeated");
				return false;
			}
			struct symtab_command *symtab = (void *) lc;
			if (lc->cmdsize < sizeof(*symtab)) {
				puts("LC_SYMTAB bad size");
				return false;
			}
			// Validate the symbols (nlist_64 array).
			size_t size = symtab->nsyms * sizeof(struct nlist_64);
			if (symtab->symoff > file_size || symtab->symoff + size > file_size) {
				puts("LC_SYMTAB bad symbols");
				return false;
			}
			// Validate that the symbol strings don't start out-of-bounds (individual
			// strings still need validation).
			if (symtab->stroff >= file_size) {
				puts("LC_SYMTAB bad strings");
				return false;
			}
			info->symtab = symtab;
		}
		// Validate the dysymtab command.
		if (lc->cmd == LC_DYSYMTAB) {
			if (info->dysymtab != NULL) {
				puts("LC_DYSYMTAB repeated");
				return false;
			}
			struct dysymtab_command *dysymtab = (void *) lc;
			if (lc->cmdsize < sizeof(*dysymtab)) {
				puts("LC_DYSYMTAB bad size");
				return false;
			}
			// Validate the external relocations.
			size_t size = dysymtab->nextrel * sizeof(struct relocation_info);
			if (dysymtab->extreloff > file_size
					|| dysymtab->extreloff + size > file_size) {
				puts("LC_DYSYMTAB bad external relocations");
				return false;
			}
			// Validate the local relocations.
			size = dysymtab->nlocrel * sizeof(struct relocation_info);
			if (dysymtab->locreloff > file_size
					|| dysymtab->locreloff + size > file_size) {
				puts("LC_DYSYMTAB bad local relocations");
				return false;
			}
			info->dysymtab = dysymtab;
		}
		// Next load command.
		lc = (void *) ((uintptr_t) lc + lc->cmdsize);
	}
	// Set the VM size.
	uint64_t vm_end = vmaddr;
	info->vm_size = vm_end - info->vm_base;
	// We need LC_SEGMENT_64, LC_SYMTAB, and LC_DYSYMTAB.
	if (!found_first_segment) {
		puts("LC_SEGMENT_64 required");
		return false;
	}
	if (info->symtab == NULL) {
		puts("LC_SYMTAB required");
		return false;
	}
	if (info->dysymtab == NULL) {
		puts("LC_DYSYMTAB required");
		return false;
	}
	// Check the LC_SYMTAB strings. Also, find the _kmod_info symbol.
	info->nlist = (void *) ((uintptr_t) header + info->symtab->symoff);
	for (uint32_t sym_idx = 0; sym_idx < info->symtab->nsyms; sym_idx++) {
		const struct nlist_64 *nl = &info->nlist[sym_idx];
		size_t stroff = info->symtab->stroff + nl->n_un.n_strx;
		if (stroff < info->symtab->stroff || stroff >= file_size) {
			puts("LC_SYMTAB bad string");
			return false;
		}
		const char *name = (void *) ((uintptr_t) header + stroff);
		size_t max_len = file_size - stroff;
		// Ensure the symbol is null-terminated in bounds.
		size_t sym_len = strnlen(name, max_len);
		if (sym_len == max_len) {
			puts("LC_SYMTAB bad string");
			return false;
		}
		// Make sure that symbols point in-bounds.
		if ((nl->n_type & N_STAB) == 0 && (nl->n_type & N_TYPE) == N_SECT) {
			uint64_t address = nl->n_value;
			if (address < info->vm_base || vm_end < address) {
				puts("LC_SYMTAB bad address");
				return false;
			}
		}
		// Handle the _kmod_info symbol.
		if (strcmp(name, "_kmod_info") == 0) {
			if (info->kmod_info != 0) {
				puts("_kmod_info repeated");
				return false;
			}
			// Verify that the kmod_info is the right type.
			if ((nl->n_type & N_STAB) != 0
					|| (nl->n_type & N_TYPE) != N_SECT) {
				puts("_kmod_info bad type");
				return false;
			}
			// Verify the kmod_info is fully in-bounds.
			uint64_t address = nl->n_value;
			if (address + sizeof(struct kmod_info) < address
					|| address + sizeof(struct kmod_info) > vm_end) {
				puts("_kmod_info bad address");
				return false;
			}
			// Store the static kext address of the kmod_info struct. This is not a
			// valid pointer until after kext_map().
			info->kmod_info = (void *) nl->n_value;
		}
	}
	// We need a kmod_info symbol.
	if (info->kmod_info == 0) {
		puts("_kmod_info required");
		return false;
	}
	// Validate the external relocations.
	info->extrel = (void *) ((uintptr_t)header + info->dysymtab->extreloff);
	bool missing_symbols = false;
	for (uint32_t er_idx = 0; er_idx < info->dysymtab->nextrel; er_idx++) {
		const struct relocation_info *er = &info->extrel[er_idx];
		if (!er->r_extern) {
			puts("External relocation not external");
			return false;
		}
		if (er->r_length != 3) {
			puts("External relocation bad size");
			return false;
		}
		if (er->r_symbolnum >= info->symtab->nsyms) {
			puts("External relocation bad symbol");
			return false;
		}
		// Make sure we can resolve the symbol against the kernelcache.
		const struct nlist_64 *nl = &info->nlist[er->r_symbolnum];
		size_t stroff = info->symtab->stroff + nl->n_un.n_strx;
		const char *name = (void *) ((uintptr_t) header + stroff);
		uint64_t resolved = kernelcache_symbol_table_lookup(name);
		if (resolved == 0) {
			if (!missing_symbols) {
				missing_symbols = true;
				puts("Could not resolve symbols:");
			}
			puts(name);
			continue;
		}
		// Check that the reloccation address is in bounds.
		uint64_t vm_addr = info->vm_base + (uint64_t) er->r_address;
		if (vm_addr < info->vm_base || vm_addr > info->vm_size
				|| vm_addr + (1uLL << er->r_length) > info->vm_size) {
			puts("External relocation bad address");
			return false;
		}
	}
	// All symbols must resolve for linking to succeed.
	if (missing_symbols) {
		return false;
	}
	// Validate the local relocations.
	info->locrel = (void *) ((uintptr_t)header + info->dysymtab->locreloff);
	for (uint32_t lr_idx = 0; lr_idx < info->dysymtab->nlocrel; lr_idx++) {
		const struct relocation_info *lr = &info->locrel[lr_idx];
		if (lr->r_extern) {
			puts("Local relocation external");
			return false;
		}
		if (lr->r_length != 3) {
			puts("Local relocation bad size");
			return false;
		}
		// Check that the reloccation address is in bounds.
		uint64_t vm_addr = info->vm_base + (uint64_t) lr->r_address;
		if (vm_addr < info->vm_base || vm_addr > info->vm_size
				|| vm_addr + (1uLL << lr->r_length) > info->vm_size) {
			puts("Local relocation bad address");
			return false;
		}
	}
	return true;
}

// Allocate memory for the kernel extension in preparation for loading.
static bool
kext_alloc(struct kext_load_info *info) {
	size_t alloc_size = (info->vm_size + 0x3fff) & ~0x3fffuL;
	if ((uint32_t) alloc_size < info->vm_size) {
		goto fail;
	}
	void *alloc = alloc_static((uint32_t) alloc_size);
	if (alloc == NULL) {
		goto fail;
	}
	info->kext = alloc;
	return true;
fail:
	puts("Could not allocate kext");
	return false;
}

// Map the kernel extension by copying the "file" data to the kext allocation. After this
// operation, all the Mach-O pointers will be updated to point to the mapped copies in the kext
// itself.
//
// Because we're relying on the OSKext loading infrastructure, we need to adjust the vmaddr of each
// LC_SEGMENT_64 and section_64 to the corresponding static kernelcache address (i.e., excluding
// the kernel slide), due to the unconditional sliding of load commands in
// OSKext::slidePrelinkedExecutable(). Also, we need to set kmod_info->address to the static
// kernelcache address of the kext for OSKext::initWithPrelinkedInfoDict().
static void
kext_map(struct kext_load_info *info) {
	const struct mach_header_64 *mh = info->header;
	const struct load_command *lc = (void *) (mh + 1);
	// Iterate the load commands to find each LC_SEGMENT_64. These are the only load commands
	// that describe mapped data in a Mach-O kext.
	for (uint32_t cmd_idx = 0; cmd_idx < mh->ncmds; cmd_idx++) {
		if (lc->cmd == LC_SEGMENT_64) {
			// Copy the file contents into the VM region.
			const struct segment_command_64 *sc = (void *) lc;
			uint64_t vmoff = sc->vmaddr - info->vm_base;
			void *vmseg = (void *) ((uintptr_t) info->kext + vmoff);
			void *fileseg = (void *) ((uintptr_t) mh + sc->fileoff);
			memcpy(vmseg, fileseg, sc->filesize);
		}
		lc = (void *) ((uintptr_t) lc + lc->cmdsize);
	}
	// Update the Mach-O load command pointers of kext_load_info to point to the newly mapped
	// Mach-O's load commands, allowing us to update them. This does not apply to the nlist,
	// extrel, or locrel fields, which may not actually be mapped by a segment.
	uintptr_t mach_o_slide = (uintptr_t) info->kext - (uintptr_t) info->header;
	info->symtab = (void *) ((uintptr_t) info->symtab + mach_o_slide);
	info->dysymtab = (void *) ((uintptr_t) info->dysymtab + mach_o_slide);
	// Update virtual addresses in the load commands, in particular, LC_SEGMENT_64, to the
	// corresponding kernelcache static addresses.
	mh = info->kext;
	lc = (void *) (mh + 1);
	for (uint32_t cmd_idx = 0; cmd_idx < mh->ncmds; cmd_idx++) {
		if (lc->cmd == LC_SEGMENT_64) {
			struct segment_command_64 *sc = (void *) lc;
			sc->vmaddr = sc->vmaddr - info->vm_base + sa_for_ptr(info->kext);
            /* XXX: Needed on 14.x */
            sc->vmaddr += kernel_slide;
			// TODO: Update sections. This is not strictly needed by XNU.
		}
		lc = (void *) ((uintptr_t) lc + lc->cmdsize);
	}
	// Set the kmod_info address and size fields, which aren't initialized by KMOD_DECL(). Once
	// again, the address needs to be a kernelcache static address.
	uintptr_t vmoff = (uintptr_t) info->kmod_info - info->vm_base;
	info->kmod_info = (void *) ((uintptr_t) info->kext + vmoff);
	info->kmod_info->address = sa_for_ptr(info->kext);
	info->kmod_info->size = info->vm_size;
}

// Apply local relocations relative to the kernel extension's true load address (i.e., including
// the kernel slide!) to ensure that pointers are adjusted for the kernel extension's new base
// address.
//
// Because we're relying on the OSKext loading infrastructure, we will need to set symtab->nsyms ==
// 0 and dysymtab->nlocrel == 0 for OSKext::slidePrelinkedExecutable().
static void
kext_relocate(struct kext_load_info *info) {
	uint64_t kext_va = va_for_ptr(info->kext);
	uintptr_t kext_va_slide = kext_va - info->vm_base;
	// Process LC_DYSYMTAB local relocations.
	for (uint32_t lr_idx = 0; lr_idx < info->dysymtab->nlocrel; lr_idx++) {
		const struct relocation_info *lr = &info->locrel[lr_idx];
		// Skip extern and non-8-byte relocations (though none should exist).
		if (lr->r_extern || lr->r_length != 3) {
			continue;
		}
		// Find the offset of the relocation pointer in the virtually mapped Mach-O and
		// slide it to the new base address. r_address is the offset from the first
		// segment's vmaddr to the vmaddr of the pointer.
		uint64_t vmoff = (uint64_t) lr->r_address - info->vm_base;
		uint64_t *reloc_ptr = (void *) ((uintptr_t) info->kext + vmoff);
		*reloc_ptr += kext_va_slide;
	}
	// Set dysymtab->nlocrel to 0 in order to prevent OSKext::slidePrelinkedExecutable() from
	// applying relocations a second time.
	info->dysymtab->nlocrel = 0;
	// Also set symtab->nsyms to 0 to prevent OSKext::slidePrelinkedExecutable() from calling
	// ml_static_slide() on each symbol address. (This is not strictly related to relocation.)
	info->symtab->nsyms = 0;
}

// Resolve symbol references from the kernel extension to the kernelcache using the preloaded
// symbol tables.
//
// Because we're relying on the OSKext loading infrastructure, we will need to set
// dysymtab->nextrel == 0 for OSKext::slidePrelinkedExecutable().
static void
kext_link(struct kext_load_info *info) {
	// Use the original unmapped kext for the string table, since it may not have been mapped
	// in a segment.
	uintptr_t strtab = (uintptr_t) info->header + info->symtab->stroff;
	// Process LC_DYSYMTAB external relocations.
	for (uint32_t er_idx = 0; er_idx < info->dysymtab->nextrel; er_idx++) {
		const struct relocation_info *er = &info->extrel[er_idx];
		// Skip non-extern and non-8-byte relocations (though none should exist).
		if (!er->r_extern || er->r_length != 3) {
			continue;
		}
		// Get the name of the symbol.
		const struct nlist_64 *nl = &info->nlist[er->r_symbolnum];
		const char *name = (void *) (strtab + nl->n_un.n_strx);
		// Resolve the symbol to the kernelcache address.
		uint64_t symbol_sa = kernelcache_symbol_table_lookup(name);
		if (symbol_sa == 0) {
			continue;
		}
		// Find the address of the external relocation pointer in the virtually mapped
		// kernel extension and replace it with the resolved dynamic address of the symbol.
		// r_address is the offset from the first segment's vmaddr to the vmaddr of the
		// pointer.
		uint64_t vmoff = (uint64_t) er->r_address - info->vm_base;
		uint64_t *link_ptr = (void *) ((uintptr_t) info->kext + vmoff);
		*link_ptr = va_for_sa(symbol_sa);

	}
	// Set dysymtab->nextrel to 0 in order to prevent OSKext::slidePrelinkedExecutable() from
	// failing.
	info->dysymtab->nextrel = 0;
}

// A __PRELINK_INFO.__info OSUnserializeXML dictionary describing the kernel extension.
static const char *prelink_info_str = "\
<dict>\
<key>CFBundleName</key>\
<string>KTRW_NNN0</string>\
<key>CFBundleIdentifier</key>\
<string>com.apple.kec.KTRW_NNN1</string>\
<key>CFBundleInfoDictionaryVersion</key>\
<string>6.0</string>\
<key>OSBundleCompatibleVersion</key>\
<string>1.0.0d1</string>\
<key>CFBundleVersion</key>\
<string>1.0.0</string>\
<key>CFBundleExecutable</key>\
<string>KTRW_HAX</string>\
<key>CFBundleSignature</key>\
<string>\?\?\?\?</string>\
<key>CFBundlePackageType</key>\
<string>KEXT</string>\
<key>CFBundleDevelopmentRegion</key>\
<string>English</string>\
<key>CFBundleShortVersionString</key>\
<string>1.0.0</string>\
<key>CFBundleSupportedPlatforms</key>\
<array>\
<string>iPhoneOS</string>\
</array>\
<key>AppleKernelExternalComponent</key>\
<true/>\
<key>_PrelinkExecutableRelativePath</key>\
<string>KTRW_HAX</string>\
<key>_PrelinkExecutableLoadAddr</key>\
<integer size=\"64\">0xADDRESS_________</integer>\
<key>_PrelinkExecutableSize</key>\
<integer size=\"64\">0xSIZE____________</integer>\
<key>_PrelinkKmodInfo</key>\
<integer size=\"64\">0xKMODINFO________</integer>\
<key>UIRequiredDeviceCapabilities</key>\
<array>\
<string>arm64</string>\
</array>\
<key>MinimumOSVersion</key>\
<string>13.3</string>\
<key>IOKitPersonalities</key>\
<dict>\
</dict>\
<key>OSBundleLibraries</key>\
<dict>\
<key>com.apple.kpi.bsd</key>\
<string>8.0.0b1</string>\
<key>com.apple.kpi.libkern</key>\
<string>8.0.0b2</string>\
<key>com.apple.kpi.mach</key>\
<string>8.0.0b2</string>\
<key>com.apple.kpi.iokit</key>\
<string>8.0.0b2</string>\
<key>com.apple.kpi.unsupported</key>\
<string>8.0</string>\
</dict>\
<key>UIDeviceFamily</key>\
<array>\
<integer IDREF=\"2\"/>\
</array>\
</dict>";

// The ID of the next kext to load, used to ensure __PRELINK_INFO dictionaries have unique keys.
static unsigned kext_id = 0;

// A table for converting a hexadecimal digit 0x0-0xf into its character representation.
static const char hex_char[16] = "0123456789abcdef";

// Format a 64-bit value as an n-character hexadecimal numeric string. This is used by
// kext_insert() to write values into the __PRELINK_INFO.__info dictionary.
static void
format_hex(char *buf, size_t n, uint64_t value) {
	for (size_t i = 0; i < n; i++) {
		buf[n - (i + 1)] = hex_char[value & 0xf];
		value >>= 4;
	}
}

// Insert the kernel extension into the kernelcache's __PRELINK_INFO.__info section to ensure that
// it has the proper VM protections set on it and has its initialization routines called during
// boot.
//
// Note that the current implementation makes several strong assumptions:
//
//     1. This is a new-style kernelcache, not an old-style kernelcache. Thus the only top-level
//        key in the __PRELINK_INFO.__info dictionary is the _PrelinkInfoDictionary key.
//     2. There is enough space at the end of the __PRELINK_INFO.__info section to insert the
//        prelink info for this kernel extension.
//     3. Only one kext is being inserted into the kernelcache, which allows us to hardcode the
//        bundle ID.
static void
kext_insert(struct kext_load_info *info) {
	// Get the kernelcache's __PRELINK_INFO.__info section.
	struct segment_command_64 *prelink_info_segment
		= macho_get_segment(mh_execute_header, "__PRELINK_INFO");
	struct section_64 *prelink_info_section
		= macho_get_section(prelink_info_segment, "__info");
	// Insert the plist before the "</array></dict>" at the end.
	char *p = ptr_for_va(prelink_info_section->addr);
	char *begin = p;
	p += prelink_info_section->size;
	while (p[-1] == 0) {
		p--;
	}
	while (strcmp(p, "</array></dict>") != 0) {
		if (p <= begin) {
			puts("Could not insert kernel extension into __PRELINK_INFO.__info");
			return;
		}
		p--;
	}
	strcpy(p, prelink_info_str);
	size_t info_size = strlen(prelink_info_str);
	// Re-insert the "</array></dict>" at the end.
	char *end = p + info_size;
	strcpy(end, "</array></dict>");
	// Patch up the info dict fields. _PrelinkKmodInfo must be unslid.
	char *nnn0 = memmem(p, info_size, "NNN0", 4);
	char *nnn1 = memmem(p, info_size, "NNN1", 4);
	char *address = memmem(p, info_size, "ADDRESS", 7);
	char *size = memmem(p, info_size, "SIZE", 4);
	char *kmodinfo = memmem(p, info_size, "KMODINFO", 8);
	format_hex(address, 16, sa_for_ptr(info->kext));
	format_hex(size, 16, info->vm_size);
	format_hex(kmodinfo, 16, sa_for_ptr(info->kmod_info));
	format_hex(nnn0, 4, kext_id);
	format_hex(nnn1, 4, kext_id);
	// Adjust the __PRELINK_INFO metadata.
	prelink_info_section->size += info_size;
	// Increment the kext ID for the next kext.
	kext_id++;
}

// Handles the "kextload" command, which is used to process the bulk uploaded data as an XNU kernel
// extension.
static void
command_kextload(const char *cmd, char *args) {
	// Grab the kext data.
	size_t kext_size = loader_xfer_recv_count;
	loader_xfer_recv_count = 0;
	if (kext_size < 0x4000) {
		puts("Kext is too small");
		return;
	}
	void *kext_header = (void *) loader_xfer_recv_data;
	// Validate and parse the kext in preparation for loading. Note that because the contents
	// are not copied out of the USB buffer, they may be concurrently overwritten with another
	// USB upload, leading to memory corruption.
	struct kext_load_info load_info = {};
	bool ok = kext_parse(kext_header, kext_size, &load_info);
	if (!ok) {
		return;
	}
	// Allocate memory for the kernel extension. No failures are permitted after this point.
	ok = kext_alloc(&load_info);
	if (!ok) {
		return;
	}
	// Copy the kernel extension segments.
	kext_map(&load_info);
	// Apply relocations at the load address.
	kext_relocate(&load_info);
	// Link the kernel extension against the kernelcache.
	kext_link(&load_info);
	// Insert the kernel extension into the kernelcache so that it will be run during boot.
	kext_insert(&load_info);
}

// ---- Kernel patching ---------------------------------------------------------------------------

// The next pre-boot hook in the chain.
static void (*next_preboot_hook)(void);


/* Future-proofing for iOS 15+ */
#define iOS_14_x                    (20)

#define VERSION_BIAS                iOS_14_x

static uint64_t g_kern_version_major = 0;
static uint64_t g_kern_version_minor = 0;
static uint32_t g_kern_version_revision = 0;

static bool getkernelv_callback(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    char *version = cacheable_stream;

    /* on all kernels, major, minor, and version are no larger than 2 chars */
    char major_s[3] = {0};
    char minor_s[3] = {0};
    char revision_s[3] = {0};

    /* skip ahead until we get a digit */
    while(!isdigit(*version))
        version++;

    for(int i=0; *version != '.'; i++, version++)
        major_s[i] = *version;

    version++;

    for(int i=0; *version != '.'; i++, version++)
        minor_s[i] = *version;

    version++;

    for(int i=0; *version != ':'; i++, version++)
        revision_s[i] = *version;

    /* currently, I only use major and minor, but I get the rest in
     * case I need them in the future */
    g_kern_version_major = atoi(major_s);
    g_kern_version_minor = atoi(minor_s);
    g_kern_version_revision = atoi(revision_s);

    if(g_kern_version_major == 19){
        printf("KTRW: This fork does not\n"
                " support iOS 13.x\n");
        ktrw_fatal_error();
    }
    else if(g_kern_version_major == iOS_14_x){
        printf("KTRW: iOS 14.x detected\n");
    }
    else{
        printf("KTRW: error: unknown\n"
                "  major %lld\n",
                g_kern_version_major);

        ktrw_fatal_error();
    }

    queue_rx_string("sep auto\n");

    return true;
}

#define MAXKEXTRANGE MAXPF

struct kextrange {
    xnu_pf_range_t *range;
    char *kext;
    char *seg;
    char *sect;
};

/* purpose of this function is to add patchfinder ranges for kexts in such
 * a way that there are no duplicates in `*ranges` */
static void add_kext_range(struct kextrange **ranges, const char *kext,
        const char *seg, const char *sect, size_t *nkextranges_out){
    size_t nkextranges = *nkextranges_out;

    if(nkextranges == MAXKEXTRANGE)
        return;

    /* first, check if this kext is already present */
    for(size_t i=0; i<nkextranges; i++){
        struct kextrange *kr = ranges[i];

        /* kext will never be NULL, otherwise, this function would have
         * no point */
        if(strcmp(kr->kext, kext) == 0){
            /* same segment? It will be the same range even if the section differs */
            if(seg && strcmp(kr->seg, seg) == 0)
                return;

            if(sect && strcmp(kr->sect, sect) == 0)
                return;
        }
    }

    /* new kext, make its range */
    struct mach_header_64 *mh = xnu_pf_get_kext_header(mh_execute_header, kext);

    if(!mh){
        printf( "KTRW: could not\n"
                "   get Mach header for\n"
                "   %s\n", kext);

        ktrw_fatal_error();
    }

    struct kextrange *kr = malloc(sizeof(struct kextrange));
    memset(kr, 0, sizeof(*kr));

    if(sect)
        kr->range = xnu_pf_section(mh, (void *)seg, (char *)sect);
    else
        kr->range = xnu_pf_segment(mh, (void *)seg);

    size_t kextl = 0, segl = 0, sectl = 0;

    kextl = strlen(kext);

    char *kn = malloc(kextl + 1);
    strcpy(kn, kext);
    kn[kextl] = '\0';
    kr->kext = kn;

    if(seg){
        segl = strlen(seg);
        char *segn = malloc(segl + 1);
        strcpy(segn, seg);
        segn[segl] = '\0';
        kr->seg = segn;
    }

    if(sect){
        sectl = strlen(sect);
        char *sectn = malloc(sectl + 1);
        strcpy(sectn, sect);
        sectn[sectl] = '\0';
        kr->sect = sectn;
    }

    ranges[nkextranges] = kr;
    *nkextranges_out = nkextranges + 1;
}

static void command_getkernelv(const char *cmd, char *args){
    xnu_pf_patchset_t *patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_8BIT);

    xnu_pf_range_t *__TEXT___const = xnu_pf_section(mh_execute_header, "__TEXT",
            "__const");

    if(!__TEXT___const){
        puts("KTRW: xnu_pf_section");
        puts("   returned NULL for");
        puts("   __TEXT:__const?");

        ktrw_fatal_error();
    }

    const char *vers = "Darwin Kernel Version ";

    /* hardcoded so clang does not generate ___chkstk_darwin calls */
    uint64_t ver[21];
    uint64_t masks[21];

    for(int i=0; i<21; i++){
        ver[i] = vers[i];
        masks[i] = 0xff;
    }

    uint64_t count = sizeof(ver) / sizeof(*ver);

    xnu_pf_maskmatch(patchset, "kernel version finder", ver, masks, count,
            false, getkernelv_callback);
    xnu_pf_emit(patchset);
    xnu_pf_apply(__TEXT___const, patchset);
    xnu_pf_patchset_destroy(patchset);
}

static void command_ktrwpf(const char *cmd, char *args){
    /* All the patchfinders in pf/pfs.h currently do 32 bit */
    xnu_pf_patchset_t *patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);

    size_t nkextranges = 0;
    struct kextrange **kextranges = malloc(sizeof(struct kextrange *) * MAXKEXTRANGE);

    for(int i=0; !PFS_END(g_all_pfs[i]); i++){
        struct pf *pf = &g_all_pfs[i][g_kern_version_major - VERSION_BIAS];

        if(IS_PF_UNUSED(pf))
            continue;

        const char *pf_kext = pf->pf_kext;
        const char *pf_segment = pf->pf_segment;
        const char *pf_section = pf->pf_section;

        if(pf_kext){
            add_kext_range(kextranges, pf_kext, pf_segment, pf_section,
                    &nkextranges);
        }

        xnu_pf_maskmatch(patchset, (char *)pf->pf_name, pf->pf_matches,
                pf->pf_masks, pf->pf_mmcount, false, pf->pf_callback);
    }

    xnu_pf_emit(patchset);

    xnu_pf_range_t *__TEXT_EXEC = xnu_pf_segment(mh_execute_header, "__TEXT_EXEC");
    xnu_pf_apply(__TEXT_EXEC, patchset);

    for(size_t i=0; i<nkextranges; i++){
        xnu_pf_range_t *range = kextranges[i]->range;
        xnu_pf_apply(range, patchset);
    }

    xnu_pf_patchset_destroy(patchset);

	g_mhaddr = va_for_sa(g_mhaddr);
}

static void anything_missing(void){
    static bool printed_err_hdr = false;

#define chk(expression, msg) \
    do { \
        if(expression){ \
            if(!printed_err_hdr){ \
                printf("KTRW: error(s) before\n" \
                        "  we boot XNU:\n"); \
                printed_err_hdr = true; \
            } \
            printf("  "msg); \
        } \
    } while (0) \

    chk(!g__disable_preemption_addr, "_disable_preemption not found\n");
    chk(!g__enable_preemption_addr, "_enable_preemption not found\n");
    chk(!g_const_boot_args_addr, "const_boot_args not found\n");
    chk(!g_IOSleep_addr, "IOSleep not found\n");
    chk(!g_kernel_map_addr, "kernel_map not found\n");
    chk(!g_kernel_memory_allocate_addr, "kernel_memory_allocate not found\n");
    chk(!g_kernel_thread_start_addr, "kernel_thread_start not found\n");
    chk(!g_ml_nofault_copy_addr, "ml_nofault_copy not found\n");
    chk(!g_paniclog_append_noflush_addr, "paniclog_append_noflush not found\n");
    chk(!g_panic_addr, "panic not found\n");
    chk(!g_thread_deallocate_addr, "thread_deallocate not found\n");
    chk(!g_vsnprintf_addr, "vsnprintf not found\n");
    chk(!g_did_patch_slidePrelinkedExecutable, "did not patch\n"
            "OSKext::slidePrelinkedExecutable\n");

    /* If we printed the error header, something is missing */
    if(printed_err_hdr)
        ktrw_fatal_error();
}

// The pre-boot hook for loading kernel extensions.
static void
kextload_preboot_hook() {
	puts("KTRW pongoOS kextload pre-boot hook");
#if DISABLE_CHECKRA1N_KERNEL_PATCHES
	puts("Skipping checkra1n pre-boot hook");
	ramdisk_size = 0;
#else // DISABLE_CHECKRA1N_KERNEL_PATCHES
	if (next_preboot_hook != NULL) {
		next_preboot_hook();
	}
#endif // DISABLE_CHECKRA1N_KERNEL_PATCHES
    anything_missing();
}

// ---- Pongo module ------------------------------------------------------------------------------

void
module_entry() {
	puts("KTRW pongoOS kextload module");
	next_preboot_hook = preboot_hook;
	preboot_hook = kextload_preboot_hook;
	mh_execute_header = xnu_header();
	kernel_slide = xnu_slide_value(mh_execute_header);
	command_register("kextload",
			"Load an XNU kernel extension at boot time",
			command_kextload);
    command_register("ktrw-getkernelv", "Get iOS and do sep auto",
            command_getkernelv);
    command_register("ktrwpf", "Run patchfinder", command_ktrwpf);
}

const char *module_name = "kextload";

struct pongo_exports exported_symbols[] = {
	{ }
};
