# -*- mode: Makefile; -*-

# A debug build of Xen and tools?
debug ?= n

XEN_COMPILE_ARCH    ?= $(shell uname -m | sed -e s/i.86/x86_32/ \
                         -e s/ppc/powerpc/ -e s/i86pc/x86_32/   \
                         -e s/amd64/x86_64/)
XEN_TARGET_ARCH     ?= $(XEN_COMPILE_ARCH)
XEN_OS              ?= $(shell uname -s)

ifeq ($(XEN_TARGET_ARCH),x86_32)
XEN_TARGET_X86_PAE  ?= y
endif

CONFIG_$(XEN_OS) := y

SHELL     ?= /bin/sh

# Tools to run on system hosting the build
HOSTCC      = gcc
HOSTCFLAGS  = -Wall -Werror -Wstrict-prototypes -O2 -fomit-frame-pointer
HOSTCFLAGS += -fno-strict-aliasing

DISTDIR     ?= $(XEN_ROOT)/dist
DESTDIR     ?= /

include $(XEN_ROOT)/config/$(XEN_OS).mk
include $(XEN_ROOT)/config/$(XEN_TARGET_ARCH).mk

ifeq ($(stubdom),y)
include $(XEN_ROOT)/extras/mini-os/Config.mk
CFLAGS += $(DEF_CFLAGS) $(ARCH_CFLAGS)
CPPFLAGS += $(DEF_CPPFLAGS) $(ARCH_CPPFLAGS) $(extra_incl)
ASFLAGS += $(DEF_ASFLAGS) $(ARCH_ASFLAGS)
LDFLAGS += $(DEF_LDFLAGS) $(ARCH_LDFLAGS)
endif

ifneq ($(EXTRA_PREFIX),)
EXTRA_INCLUDES += $(EXTRA_PREFIX)/include
EXTRA_LIB += $(EXTRA_PREFIX)/$(LIBLEAFDIR)
endif

# cc-option: Check if compiler supports first option, else fall back to second.
# Usage: cflags-y += $(call cc-option,$(CC),-march=winchip-c6,-march=i586)
cc-option = $(shell if test -z "`$(1) $(2) -S -o /dev/null -xc \
              /dev/null 2>&1`"; then echo "$(2)"; else echo "$(3)"; fi ;)

# cc-ver: Check compiler is at least specified version. Return boolean 'y'/'n'.
# Usage: ifeq ($(call cc-ver,$(CC),0x030400),y)
cc-ver = $(shell if [ $$((`$(1) -dumpversion | awk -F. \
           '{ printf "0x%02x%02x%02x", $$1, $$2, $$3}'`)) -ge $$(($(2))) ]; \
           then echo y; else echo n; fi ;)

# cc-ver-check: Check compiler is at least specified version, else fail.
# Usage: $(call cc-ver-check,CC,0x030400,"Require at least gcc-3.4")
cc-ver-check = $(eval $(call cc-ver-check-closure,$(1),$(2),$(3)))
define cc-ver-check-closure
    ifeq ($$(call cc-ver,$$($(1)),$(2)),n)
        override $(1) = echo "*** FATAL BUILD ERROR: "$(3) >&2; exit 1;
        cc-option := n
    endif
endef

ifeq ($(debug),y)
CFLAGS += -g
endif

CFLAGS += -fno-strict-aliasing

CFLAGS += -std=gnu99

CFLAGS += -Wall -Wstrict-prototypes

# -Wunused-value makes GCC 4.x too aggressive for my taste: ignoring the
# result of any casted expression causes a warning.
CFLAGS += -Wno-unused-value

HOSTCFLAGS += $(call cc-option,$(HOSTCC),-Wdeclaration-after-statement,)
CFLAGS     += $(call cc-option,$(CC),-Wdeclaration-after-statement,)

LDFLAGS += $(foreach i, $(EXTRA_LIB), -L$(i)) 
CFLAGS += $(foreach i, $(EXTRA_INCLUDES), -I$(i))

# Enable XSM security module.  Enabling XSM requires selection of an 
# XSM security module (FLASK_ENABLE or ACM_SECURITY).
XSM_ENABLE ?= n
FLASK_ENABLE ?= n
ACM_SECURITY ?= n

# Optional components
XENSTAT_XENTOP     ?= y
VTPM_TOOLS         ?= n
LIBXENAPI_BINDINGS ?= n
PYTHON_TOOLS       ?= y
CONFIG_MINITERM    ?= n
CONFIG_LOMOUNT     ?= n

-include $(XEN_ROOT)/.config
