CFLAGS-libos = -L../../../build/libos -I../../include

NATIVE_TESTS_CPP = $(patsubst %.cpp,%,$(wildcard *.cpp))
NATIVE_TESTS_STATIC = static
NATIVE_TESTS = $(filter-out $(NATIVE_TESTS_STATIC),$(patsubst %.c,%,$(wildcard *.c)))

targets = $(NATIVE_TESTS) $(NATIVE_TESTS_CPP) $(NATIVE_TESTS_STATIC) \
	  manifest static.manifest pal pal_sec
rtarget = helloworld clone vfork fork exec vfork_exec errno dup time \
	  helloworld.pthread udp tcp unix file dev
clean-extra = clean-exec

level = ../
include ../Makefile

test-helloworld = grep -q "Hello World" OUTPUT
test-clone = grep -q "in the child: pid = 2" OUTPUT
test-vfork = grep -q "Hello, Dad!" OUTPUT
test-fork = grep -q "Hello, Dad!" OUTPUT
test-exec = grep -q "Hello World" OUTPUT
test-file = grep -q "Hello World" OUTPUT && [ ! -f testfile ]
test-errno = grep -q "errno = 22" OUTPUT
test-dup = grep -q "Hello World" OUTPUT
test-time = grep -q "Current timestamp" OUTPUT
test-helloworld.pthread = grep -q "Hello World" OUTPUT

%.manifest: %.manifest.template
	rm -rf $@
	cp $@.template $@

$(NATIVE_TESTS): %: %.c
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(if $(findstring .libos,$@),$(CFLAGS-libos),) -o $@ $< \
	$(shell echo $@ | sed 's/^[^\.]*//g' | sed 's/\./ -l/g')

$(NATIVE_TESTS_CPP): %: %.cpp
	@echo [ $@ ]
	@$(CC) $(CFLAGS) -o $@ $< \
	$(shell echo $@ | sed 's/^[^\.]*//g' | sed 's/\./ -l/g')

$(NATIVE_TESTS_STATIC): %: %.c
	@echo [ $@ ]
	@$(CC) $(CFLAGS) -o $@ -static $< \
	$(shell echo $@ | sed 's/^[^\.]*//g' | sed 's/\./ -l/g')

test-helloworld = grep -q "Hello world" OUTPUT

clean-exec:
	find -type f -executable -exec rm {} \;
	rm -rf manifest static.manifest pal pal_sec
