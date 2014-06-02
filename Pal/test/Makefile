CC	= gcc
CFLAGS	= -Wall -O2 -std=gnu99 -fgnu89-inline -fno-builtin -nostdlib -e main \
	  -I../include/pal -I../lib -L../src -lpal

rtarget	= HelloWorld File Failure Thread Fork Event \
	  Process Exception Memory Pipe Tcp Udp Yield Broadcast
target	= $(rtarget) Ipc Server Wait HandleSend Select

graphene_lib = ../lib/graphene-lib.a
pal_lib = ../src/libpal.so
headers = $(wildcard ../include/pal/*.h)

all:	$(target) manifest

debug:	CC=gcc -g
debug:	$(target) manifest

manifest: manifest.template
	[ ! -f manifest ] || mv -f manifest manifest.backup
	cp manifest.template manifest

# Regression Test
rtest:	$(rtarget)
	for d in $(rtarget); \
	do \
		make run-$$d || return $$?; \
	done

test-HelloWorld = grep -q "Hello World" OUTPUT
test-File = grep -q "Hello World" OUTPUT
test-Failure = grep -q "Function not supported" OUTPUT
test-Exception = test `grep -c "failure in the handler" OUTPUT` -eq 30
test-Pipe = test `grep -c "Hello World" OUTPUT` -eq 10
test-Tcp = test `grep -c "Hello World" OUTPUT` -eq 10
test-Udp = test `grep -c "Hello World" OUTPUT` -eq 10

$(patsubst %,run-%,$(rtarget)): run-%: %
	@echo [ run $< $(value arg-$<) ]
	@./libpal.so $< $(value arg-$<) > OUTPUT
	@$(value test-$<)
	@rm -rf OUTPUT

%.e: %.c $(libobj) $(headers)
	@echo [ $@ ]
	@$(CC) $(CFLAGS) -E $< -o $@

$(target): %: %.c $(graphene_lib) $(pal_lib)
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -rf $(target)
	[ ! -f manifest ] || mv manifest manifest.backup
	find -type f -executable -exec rm {} \;
