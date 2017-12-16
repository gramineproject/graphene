include src/Makefile.Host

DIRS = src test regression

.PHONY: all clean
all clean:
	for d in $(DIRS); \
	do \
		$(MAKE) -C $$d $@ || exit $?; \
	done

.PHONY: test
test:
	$(MAKE) -C test test

.PHONY: pack
pack:
	$(MAKE) -C test pack
	$(MAKE) -C regression pack
