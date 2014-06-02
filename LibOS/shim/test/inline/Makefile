INLINE_TESTS_CPP = $(patsubst %.cpp,%,$(wildcard *.cpp))
INLINE_TESTS = $(patsubst %.c,%,$(wildcard *.c))

rtarget = helloworld fork vfork
targets = $(rtarget) manifest pal
clean-extra = clean-exec

level = ../
include ../Makefile

$(INLINE_TESTS): %: %.c $(libs)
	@echo [ $@ ]
	@$(CC) $(CFLAGS-debug) -nostdlib -nostartfiles -e main $(LDFLAGS-debug) -o $@ $^

$(INLINE_TESTS_CPP): %: %.cpp $(libs)
	@echo [ $@ ]
	@$(CXX) $(CFLAGS-debug) -nostdlib -nostartfiles -e main $(LDFLAGS-debug) -o $@ $^

test-helloworld = grep -q "Hello world" OUTPUT
test-printf = grep -q "1 printf printf" OUTPUT
test-fork = grep -q "Hello, Dad" OUTPUT && grep -q "Hello, Kid" OUTPUT
test-vfork = grep -q "Hello, Dad" OUTPUT && grep -q "Hello, Kid" OUTPUT

clean-exec:
	find -type f -executable -exec rm {} \;
	rm -rf manifest libpal.so
