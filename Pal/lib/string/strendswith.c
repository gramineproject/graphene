#include <api.h>

bool strendswith(const char* haystack, const char* needle) {
    size_t haystack_len = strlen(haystack);
    size_t needle_len = strlen(needle);

    if (haystack_len < needle_len) {
        return false;
    }

    return !memcmp(&haystack[haystack_len - needle_len], needle, needle_len);
}
