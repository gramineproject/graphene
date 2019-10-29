include ../../../../../Makefile.configs

CFLAGS := -Wall -Wextra -O2 -maes -std=c11 \
	-fno-omit-frame-pointer \
	-D_POSIX_C_SOURCE=200809L

ifeq ($(DEBUG),1)
CC += -gdwarf-2 -g3
CFLAGS += -DDEBUG
export DEBUG
endif

ifeq ($(WERROR),1)
CFLAGS += -Werror
endif

headers = $(wildcard *.h) ../protected_files.h
objs = util pf_util pf_crypt
bins = pf_crypt pf_tamper

.PHONY: all
all: $(bins)

protected_files.o: ../protected_files.c
	$(CC) $(CFLAGS) $(CFLAGS-$@) -c -o $@ $<

$(addsuffix .o,$(objs)): %.o: %.c $(headers)
	$(CC) $(CFLAGS) $(CFLAGS-$@) -c -o $@ $<

pf_crypt: pf_crypt.o util.o pf_util.o protected_files.o
	@echo [ host/Linux-SGX/tools/$@ ]
	@$(CC) $(CFLAGS) -Wl,-z,relro,-z,now $^ -lc -lcrypto -o $@

pf_tamper: pf_tamper.o util.o pf_util.o protected_files.o
	@echo [ host/Linux-SGX/tools/$@ ]
	@$(CC) $(CFLAGS) -Wl,-z,relro,-z,now $^ -lc -lcrypto -o $@

clean:
	@rm -f *.o
	@rm -f $(bins)
