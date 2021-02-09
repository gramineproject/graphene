#include "common.h"

int main(int argc, char* argv[]) {
    if (argc < 4)
        fatal_error("Usage: %s <input_dir> <intermedia_tmpfs_dir> <output_dir>\n", argv[0]);

    setup();

    char* input_dir = argv[1];
    char* tmpfs_dir = argv[2];
    char* output_dir = argv[3];

    // Process input directory
    DIR* dfd = opendir(input_dir);
    if (!dfd)
        fatal_error("Failed to open input directory %s: %s\n", input_dir, strerror(errno));
    printf("opendir(%s) OK\n", input_dir);

    struct dirent* de = NULL;
    while ((de = readdir(dfd)) != NULL) {
        printf("readdir(%s) OK\n", de->d_name);
        if (!strcmp(de->d_name, "."))
            continue;
        if (!strcmp(de->d_name, ".."))
            continue;

        // assume files have names that are their sizes as string
        size_t input_path_size = strlen(input_dir) + 1 + strlen(de->d_name) + 1;
        size_t tmpfs_path_size = strlen(tmpfs_dir) + 1 + strlen(de->d_name) + 1;
        char* input_path = alloc_buffer(input_path_size);
        char* tmpfs_path = alloc_buffer(tmpfs_path_size);

	snprintf(input_path, input_path_size, "%s/%s", input_dir, de->d_name);
        snprintf(tmpfs_path, tmpfs_path_size, "%s/%s", tmpfs_dir, de->d_name);
	copy_file_tmpfs(input_path, tmpfs_path);

        free(input_path);
        free(tmpfs_path);
    }

    dfd = opendir(tmpfs_dir);
    if (!dfd)
        fatal_error("Failed to open input directory %s: %s\n", tmpfs_dir, strerror(errno));
    printf("opendir(%s) OK\n", tmpfs_dir);

    de = NULL;
    while ((de = readdir(dfd)) != NULL) {
        printf("readdir(%s) OK\n", de->d_name);
        if (!strcmp(de->d_name, "."))
            continue;
        if (!strcmp(de->d_name, ".."))
            continue;

        // assume files have names that are their sizes as string
        size_t tmpfs_path_size = strlen(tmpfs_dir) + 1 + strlen(de->d_name) + 1;
        size_t output_path_size = strlen(output_dir) + 1 + strlen(de->d_name) + 1;
        char* tmpfs_path = alloc_buffer(tmpfs_path_size);
        char* output_path = alloc_buffer(output_path_size);

        snprintf(tmpfs_path, tmpfs_path_size, "%s/%s", tmpfs_dir, de->d_name);
        snprintf(output_path, output_path_size, "%s/%s", output_dir, de->d_name);
        copy_file_tmpfs(tmpfs_path, output_path);

        free(tmpfs_path);
        free(output_path);
    }

    return 0;
}
