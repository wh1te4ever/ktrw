TARGET = pongo_kext_loader

DEBUG ?= 0

CFLAGS = -O2 -Wall -Werror -Wno-incompatible-function-pointer-types -Wno-c2x-extensions -Wno-strict-prototypes

ifneq ($(DEBUG),0)
CFLAGS += -DDEBUG=$(DEBUG)
endif

SOURCES = source/pongo_kext_loader.c

HEADERS =

FRAMEWORKS = -framework IOKit -framework CoreFoundation

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(DEFINES) $(LDFLAGS) $(FRAMEWORKS) -o $@ $(SOURCES)

clean:
	rm -f -- $(TARGET)
