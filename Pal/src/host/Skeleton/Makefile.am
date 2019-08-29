# Add host-specific compilation rules here

CFLAGS  = -Wall -fPIC -O2 -std=gnu99 -fgnu89-inline -Wall -U_FORTIFY_SOURCE -fno-builtin
ASFLAGS = -DPIC -DSHARED -fPIC -DASSEMBLER -Wa,--noexecstack -x assembler-with-cpp

ifeq ($(WERROR),1)
CFLAGS += -Werror
endif
