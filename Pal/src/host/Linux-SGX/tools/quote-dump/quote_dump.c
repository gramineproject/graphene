#include <stdlib.h>

#include "attestation.h"
#include "util.h"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        ERROR("Usage: %s <filename>\n", argv[0]);
        return -EINVAL;
    }

    const char* path = argv[1];

    ssize_t quote_size = 0;
    uint8_t* quote = read_file(path, &quote_size);
    if (!quote)
        return -1;

    display_quote(quote, quote_size);
    return 0;
}
