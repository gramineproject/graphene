#include "api.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"

static const char* get_norm_path_cases[][2] = {
    {"/", "/"},
    {"/a/b/c", "/a/b/c"},
    {"/a/../b", "/b"},
    {"/../a", "/a"},
    {"/../../../../../a", "/a"},
    {"/../a/../../b", "/b"},
    {"/../..a/b", "/..a/b"},
    {"/a/..", "/"},
    {"/a/.", "/a"},
    {"/.//a//./b", "/a/b"},
    {"///////.////////////./", "/"},
    {"/...././a/../././.../b/.....", "/..../.../b/....."},
    {"a/b/c", "a/b/c"},
    {"a/../b", "b"},
    {"../a", "../a"},
    {"../../../../../a", "../../../../../a"},
    {"../a/../../b", "../../b"},
    {"../..a/b", "../..a/b"},
    {"a/..", ""},
    {"a/.", "a"},
};

static const char* get_base_name_cases[][2] = {
    {"/", ""},      {"/a", "a"},   {"/a/b/c", "c"},           {"/..a/b", "b"},
    {"", ""},       {"../a", "a"}, {"../../../../../a", "a"}, {"..a/b", "b"},
    {"a/b/c", "c"},
};

#define print_err(name, i, ...)                                 \
    do {                                                        \
        pal_printf("%s: case %lu (\"%s\") ", name, i, cases[i][0]); \
        pal_printf(__VA_ARGS__);                                \
    } while (0)

static const char* (*cases)[2];
static size_t cases_len;
static int (*func_to_test)(const char*, char*, size_t*);
static const char* func_name;

static int run_test(void) {
    char buf[URI_MAX] = {0};

    for (size_t i = 0; i < cases_len; i++) {
        size_t size = sizeof(buf);
        int ret     = func_to_test(cases[i][0], buf, &size);

        if (ret < 0) {
            print_err(func_name, i, "failed with error: %s\n", pal_strerror(ret));
            return 1;
        }

        if (strlen(buf) != size) {
            print_err(func_name, i, "returned wrong size: %zu\n", size);
            return 1;
        }

        if (strcmp(cases[i][1], buf) != 0) {
            print_err(func_name, i, "returned: \"%s\", instead of: \"%s\"\n", buf, cases[i][1]);
            return 1;
        }
    }
    return 0;
}

int main(void) {
    cases        = get_norm_path_cases;
    cases_len    = ARRAY_SIZE(get_norm_path_cases);
    func_to_test = get_norm_path;
    func_name = "get_norm_path";
    if (run_test()) {
        return 1;
    }

    cases        = get_base_name_cases;
    cases_len    = ARRAY_SIZE(get_base_name_cases);
    func_to_test = get_base_name;
    func_name = "get_base_name";
    if (run_test()) {
        return 1;
    }

    pal_printf("Success!\n");
    return 0;
}
