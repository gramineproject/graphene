.PHONY: all debug clean install

all debug clean install:
	for d in Pal LibOS; \
	do \
		make -C $$d $@; \
	done
