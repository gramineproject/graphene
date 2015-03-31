MAKEFLAGS += --check-symlink-times

SRC_DIRS := src
TESTS_DIRS := test
DIRS := ${SRC_DIRS} ${TESTS_DIRS}

all debug clean: ${DIRS}
	for d in ${DIRS}; \
	do \
		make $@ -C $$d; \
	done
