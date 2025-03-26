TARGET = ktrw_usb_proxy

DEBUG ?= 0

CFLAGS = -O2 -Wall -Werror
CFLAGS += -Wno-deprecated-declarations

ifneq ($(DEBUG),0)
CFLAGS += -DDEBUG=$(DEBUG)
endif

SOURCES = main.c

HEADERS =

FRAMEWORKS = -framework IOKit -framework CoreFoundation

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(DEFINES) $(LDFLAGS) $(FRAMEWORKS) -o $@ $(SOURCES)

clean:
	rm -f -- $(TARGET)
