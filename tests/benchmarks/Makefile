BENCHMARKS = \
	 helloworld \
	 write_pages

.PHONY: all
all: $(BENCHMARKS)
	$(MAKE) -C http-root $@

.PHONY: clean
clean:
	$(MAKE) -C http-root $@
	$(RM) $(BENCHMARKS)
