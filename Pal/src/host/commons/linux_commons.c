#include "api.h"
#include "linux_commons.h"

/* This version is too dumb to be shared by the whole repository and should be removed once we get
 * a proper stdlib (like musl). */
static double atod(const char* s) {
    double ret = 0.0;
    char* end = NULL;
    double base, fractional;

    base = strtol(s, &end, 10);

    if (*end == '.') {
        s = end + 1;
        fractional = strtol(s, &end, 10);
        while (s != end) {
            fractional /= 10.0;
            s++;
        }
        ret = base + fractional;
    }

    return ret;
}

double get_bogomips_from_buf(const char* buf, size_t size) {
    /* We could use strstr if graphene had one. */
    /* Each prefix of the word "bogomips" occurs only once in the whole word, hence this works. */
    const char* const word = "bogomips";
    const size_t word_size = strlen(word);
    size_t i = 0,
           j = 0;

    if (word_size > size) {
        return 0.0;
    }

    while (i < size - word_size && buf[i]) {
        j = 0;
        while (j < word_size && buf[i + j] == word[j]) {
            j++;
        }

        if (j) {
            i += j;
        } else {
            i += 1;
        }

        if (j == word_size) {
            /* buf is null-terminated, so no need to check size. word does not contain neither
             * spaces nor tabs, hence we can forward global index `i`, even if we do not return
             * here. */
            while (buf[i] == ' ' || buf[i] == '\t') {
                i++;
            }
            if (buf[i] == ':') {
                return atod(&buf[i + 1]);
            }
        }
    }

    return 0.0;
}

