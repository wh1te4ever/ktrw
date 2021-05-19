TARGET = kextload.pongo-module

ARCH = arm64
SDK  = iphoneos

SYSROOT := $(shell xcrun --sdk $(SDK) --show-sdk-path)
ifeq ($(SYSROOT),)
$(error Could not find SDK $(SDK))
endif
CLANG := $(shell xcrun --sdk $(SDK) --find clang)
CC := $(CLANG) -isysroot $(SYSROOT) -arch $(ARCH)

CFLAGS  =  -fno-builtin -fno-common -mkernel
CFLAGS += -Isource/third_party
CFLAGS += -O2
CFLAGS += -Wall -Wpedantic -Wno-gnu -Wno-language-extension-token -Wconversion

LDFLAGS  = -Xlinker -kext -nostdlib -Xlinker -fatal_warnings

SOURCES = source/asm.c \
		  source/common.c \
		  source/pongo_kextload.c \
		  source/pf/14/pf.c

HEADERS = source/third_party/pongo.h \
		  source/asm.h \
		  source/common.h \
		  source/pf/offsets.h \
		  source/pf/pf_common.h \
		  source/pf/pfs.h \
		  source/pf/14/pf.h

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(DEFINES) $(LDFLAGS) -o $@ $(SOURCES)

symbols: $(TARGET)
	@nm -u $(TARGET)

clean:
	rm -rf -- $(TARGET).$(ARCH).ld
	rm -f -- $(TARGET)
