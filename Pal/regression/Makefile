SYS ?= $(shell gcc -dumpmachine)

CC	= gcc -g
CFLAGS	= -Wall -O2 -std=gnu99 -fgnu89-inline -fno-builtin -nostdlib \
	  -I../include/pal -I../lib

target	= $(patsubst %.c,%,$(wildcard *.c)) \
	  manifest $(patsubst %.manifest.template,%.manifest,$(wildcard *.manifest.template))

preloads    = $(patsubst %.c,%,$(wildcard *.so.c))
executables = $(filter-out $(preloads),$(patsubst %.c,%,$(wildcard *.c)))
manifests   = manifest $(patsubst %.manifest.template,%.manifest,$(wildcard *.manifest.template))

target = $(executables) $(preloads) $(manifests)

graphene_lib = ../lib/graphene-lib.a
pal_lib = ../src/libpal.so
headers = $(wildcard ../include/pal/*.h)

all:	$(target)

manifest_rules = \
	-e 's:\$$(PAL):$(abspath $(PWD)/../src/pal):g' \
	-e 's:\$$(PWD):$(PWD)/:g' \
	$(extra_rules)

manifest: manifest.template
	rm -f $@
	sed $(manifest_rules) $< >$@
	chmod +x $@

%.manifest: %.manifest.template
	rm -f $@
	sed $(manifest_rules) $< >$@
	chmod +x $@

../src/user_shared_start.o ../src/user_start.o: ../src/user_start.S
	make -C ../src $(notdir $@)

ifeq ($(SYS),x86_64-linux-gnu)
$(preloads): %.so: %.so.c ../src/user_shared_start.o \
	$(graphene_lib) $(pal_lib) ../include/pal/pal.h
	@echo [ $@ ]
	@$(CC) -shared -fPIC $(CFLAGS) $^ -o $@

$(executables): %: %.c ../src/user_start.o \
	$(graphene_lib) $(pal_lib) $(preloads) ../include/pal/pal.h
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $^ -o $@

.PHONY: pack
pack: $(preloads) $(executables)
	tar -czf .packed/test.tar.gz $^
else
$(preloads) $(executables): .packed/test.tar.gz
	tar -xmozf $<
endif

PYTHONENV = "PYTHONPATH=../../Scripts"

regression: $(target)
	@echo "\n\nBasic Bootstrapping:"
	@for f in $(wildcard 00_*.py); do env $(PYTHONENV) python $$f; done
	@echo "\n\nException Handling:"
	@for f in $(wildcard 01_*.py); do env $(PYTHONENV) python $$f; done
	@echo "\n\nSingle-Process Functionalities:"
	@for f in $(wildcard 02_*.py); do env $(PYTHONENV) python $$f; done
	@echo "\n\nProcess Creation:"
	@for f in $(wildcard 03_*.py); do env $(PYTHONENV) python $$f; done
	@echo "\n\nMulti-Process Functionalities:"
	@for f in $(wildcard 04_*.py); do env $(PYTHONENV) python $$f; done
	@echo "\n\nReference Monitor (Optional):"
	@for f in $(wildcard 05_*.py); do env $(PYTHONENV) python $$f; done
	@echo "\n\n"

clean:
	rm -rf $(target) *.tmp
