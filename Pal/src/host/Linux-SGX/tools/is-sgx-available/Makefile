PREFIX ?= /usr/local

.PHONY: all
all: is_sgx_available

.PHONY: install
install:
	install -D is_sgx_available -t ${PREFIX}/bin

.PHONY: clean
clean:
	$(RM) is_sgx_available

.PHONY: distclean
distclean: clean

is_sgx_available: is_sgx_available.cpp
	g++ -O2 -std=c++14 -DNDEBUG -Wall -Wextra -Wno-multichar -masm=intel $< -o $@
