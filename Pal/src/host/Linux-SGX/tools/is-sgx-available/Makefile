.PHONY: all
all: is_sgx_available

.PHONY: clean
clean:
	$(RM) is_sgx_available

is_sgx_available: is_sgx_available.cpp
	g++ -O2 -DNDEBUG -Wall -Wextra -Wno-multichar -masm=intel $< -o $@
