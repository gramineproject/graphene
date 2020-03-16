.PHONY: all
all: is_sgx_available

.PHONY: clean
clean:
	rm is_sgx_available

is_sgx_available: is_sgx_available.cpp
	g++ -O2 -DNDEBUG -Wall -Wextra -Wno-multichar -masm=intel is_sgx_available.cpp -o is_sgx_available
