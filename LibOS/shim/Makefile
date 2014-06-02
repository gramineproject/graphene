MAKEFLAGS += --check-symlink-times

TARGET := all debug clean
SRC_DIRS := src
TESTS_DIRS := test
DIRS := ${SRC_DIRS} ${TESTS_DIRS}

${TARGET}: ${DIRS}
	for d in ${DIRS}; \
	do \
		make $@ -C $$d; \
	done
